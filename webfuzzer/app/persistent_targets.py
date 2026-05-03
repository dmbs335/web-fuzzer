"""Persistent target mapping and timeout helpers for CLI assembly."""

from __future__ import annotations

import sys
_PERSISTENT_MODULE_MAP = {
    "targets/sanitizer_dompurify.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_module.js"),
    "targets/sanitizer_sanitize_html.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_sanitize_html_module.js"),
    "targets/sanitizer_jsxss.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_jsxss_module.js"),
    "targets/sanitizer_dompurify_mxss.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_mxss_module.js"),
    "targets/sanitizer_dompurify_mxss_browser.js": ("node --expose-gc --max-old-space-size=1024 targets/persistent_wrapper_async.js", "targets/sanitizer_dompurify_mxss_browser_module.js"),
    # DOMPurify config variant targets
    "targets/sanitizer_dompurify_mxss_templates.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_mxss_templates_module.js"),
    "targets/sanitizer_dompurify_mxss_xhtml.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_mxss_xhtml_module.js"),
    "targets/sanitizer_dompurify_mxss_wholedoc.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_mxss_wholedoc_module.js"),
    "targets/sanitizer_dompurify_mxss_custom.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_mxss_custom_module.js"),
    "targets/sanitizer_jsxss_mxss.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_jsxss_mxss_module.js"),
    "targets/sanitizer_sanitize_html_mxss.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_sanitize_html_mxss_module.js"),
    # Browser-in-the-loop mXSS targets (Playwright + Chromium)
    "targets/sanitizer_jsxss_mxss_browser.js": ("node --expose-gc --max-old-space-size=1024 targets/persistent_wrapper_async.js", "targets/sanitizer_jsxss_mxss_browser_module.js"),
    "targets/sanitizer_sanitize_html_mxss_browser.js": ("node --expose-gc --max-old-space-size=1024 targets/persistent_wrapper_async.js", "targets/sanitizer_sanitize_html_mxss_browser_module.js"),
    # Sanitizer differential targets
    "targets/sanitizer_dompurify_diff.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_diff_module.js"),
    "targets/sanitizer_sanitize_html_diff.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_sanitize_html_diff_module.js"),
    "targets/sanitizer_jsxss_diff.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_jsxss_diff_module.js"),
    "targets/url_node_whatwg.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/url_node_whatwg_module.js"),
    "targets/url_node_legacy.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/url_node_legacy_module.js"),
    "targets/url_python_urllib.py": ("python targets/persistent_wrapper.py", "targets/url_python_urllib_module.py"),
    "targets/url_python_rfc3986.py": ("python targets/persistent_wrapper.py", "targets/url_python_rfc3986_module.py"),
    # New URL parser targets
    "targets/url_curl.py": ("python targets/persistent_wrapper.py", "targets/url_curl_module.py"),
    "targets/url_php_parse_url.php": ("python targets/persistent_wrapper.py", "targets/url_php_parse_url_module.py"),
    "targets/url_wget.py": ("python targets/persistent_wrapper.py", "targets/url_wget_module.py"),
    # SAML targets
    "targets/saml_xmlcrypto.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/saml_xmlcrypto_module.js"),
    "targets/saml_samlify.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/saml_samlify_module.js"),
    "targets/saml_nodesaml.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/saml_nodesaml_module.js"),
    "targets/saml_signxml.py": ("python targets/persistent_wrapper.py", "targets/saml_signxml_module.py"),
    "targets/saml_python3saml.py": ("python targets/persistent_wrapper.py", "targets/saml_python3saml_module.py"),
    "targets/saml_rubysaml.rb": ("C:/Ruby32-x64/bin/ruby targets/persistent_wrapper.rb", "targets/saml_rubysaml_module.rb"),
    "targets/saml_phpsaml.php": ("C:/Users/dmbs3/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe/php.exe targets/persistent_wrapper.php", "targets/saml_phpsaml_module.php"),
    # JWT targets
    "targets/jwt_python_strict.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_strict_module.py"),
    "targets/jwt_node_permissive.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_permissive_module.js"),
    "targets/jwt_node_pac4j_like.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_pac4j_like_module.js"),
    "targets/jwt_python_jwcrypto.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_jwcrypto_module.py"),
    "targets/jwt_node_jsonwebtoken.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_jsonwebtoken_module.js"),
    "targets/jwt_node_jose4.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_jose4_module.js"),
    "targets/jwt_python_pyjwt.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_pyjwt_module.py"),
    "targets/jwt_python_jose.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_jose_module.py"),
    "targets/jwt_node_fastjwt.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_fastjwt_module.js"),
    # JWT RSA targets (§1-2, §2-3, §7-1 keyless attacks)
    "targets/jwt_node_jsonwebtoken_rsa.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_jsonwebtoken_rsa_module.js"),
    "targets/jwt_python_pyjwt_rsa.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_pyjwt_rsa_module.py"),
    "targets/jwt_python_jwcrypto_rsa.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_jwcrypto_rsa_module.py"),
    # JWT EC targets (§1-3 algorithm downgrade, §3-2 ECDSA curve confusion)
    "targets/jwt_python_pyjwt_ec.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_pyjwt_ec_module.py"),
    "targets/jwt_python_jwcrypto_ec.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_jwcrypto_ec_module.py"),
    # JWT Authlib target
    "targets/jwt_python_authlib.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_authlib_module.py"),
    "targets/jwt_node_jsonwebtoken_ec.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_jsonwebtoken_ec_module.js"),
    "targets/jwt_node_jose4_ec.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_jose4_ec_module.js"),
    # Multi-language sanitizer differential targets
    "targets/sanitizer_bleach_diff.py": ("python targets/persistent_wrapper.py", "targets/sanitizer_bleach_diff_module.py"),
    "targets/sanitizer_nh3_diff.py": ("python targets/persistent_wrapper.py", "targets/sanitizer_nh3_diff_module.py"),
    "targets/sanitizer_lxml_diff.py": ("python targets/persistent_wrapper.py", "targets/sanitizer_lxml_diff_module.py"),
    "targets/sanitizer_sanitize_diff.rb": ("C:/Ruby32-x64/bin/ruby targets/persistent_wrapper.rb", "targets/sanitizer_sanitize_diff_module.rb"),
    "targets/sanitizer_loofah_diff.rb": ("C:/Ruby32-x64/bin/ruby targets/persistent_wrapper.rb", "targets/sanitizer_loofah_diff_module.rb"),
    "targets/sanitizer_htmlpurifier_diff.php": ("C:/Users/dmbs3/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe/php.exe targets/persistent_wrapper.php", "targets/sanitizer_htmlpurifier_diff_module.php"),
    # Cookie targets
    "targets/cookie_python_stdlib.py": ("python targets/persistent_wrapper.py", "targets/cookie_python_stdlib_module.py"),
    "targets/cookie_node_setcookieparser.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/cookie_node_setcookieparser_module.js"),
    "targets/cookie_node_toughcookie.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/cookie_node_toughcookie_module.js"),
    "targets/cookie_node_cookie.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/cookie_node_cookie_module.js"),
    "targets/cookie_ruby_webrick.rb": ("C:/Ruby32-x64/bin/ruby targets/persistent_wrapper.rb", "targets/cookie_ruby_webrick_module.rb"),
    # OAuth targets
    "targets/oauth_redirect_oidcprovider.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/oauth_redirect_oidcprovider_module.js"),
    "targets/oauth_redirect_nodeoauth2.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/oauth_redirect_nodeoauth2_module.js"),
    "targets/oauth_redirect_authlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_redirect_authlib_module.py"),
    "targets/oauth_scope_oauthlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_scope_oauthlib_module.py"),
    # OAuth real-library scope targets
    "targets/oauth_scope_authlib_real.py": ("python targets/persistent_wrapper.py", "targets/oauth_scope_authlib_real_module.py"),
    "targets/oauth_scope_oauthlib_real.py": ("python targets/persistent_wrapper.py", "targets/oauth_scope_oauthlib_real_module.py"),
    # OAuth PKCE targets
    "targets/oauth_pkce_authlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_pkce_authlib_module.py"),
    "targets/oauth_pkce_oauthlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_pkce_oauthlib_module.py"),
    "targets/oauth_pkce_node.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/oauth_pkce_node_module.js"),
    # OAuth token request targets
    "targets/oauth_tokenreq_authlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_tokenreq_authlib_module.py"),
    "targets/oauth_tokenreq_oauthlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_tokenreq_oauthlib_module.py"),
    "targets/oauth_tokenreq_node.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/oauth_tokenreq_node_module.js"),
    # OAuth token response targets
    "targets/oauth_tokenresp_authlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_tokenresp_authlib_module.py"),
    "targets/oauth_tokenresp_oauthlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_tokenresp_oauthlib_module.py"),
    "targets/oauth_tokenresp_node.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/oauth_tokenresp_node_module.js"),
    # DPoP targets (RFC 9449)
    "targets/dpop_node_jose.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/dpop_node_jose_module.js"),
    "targets/dpop_python_authlib.py": ("python targets/persistent_wrapper.py", "targets/dpop_python_authlib_module.py"),
    "targets/dpop_python_strict.py": ("python targets/persistent_wrapper.py", "targets/dpop_python_strict_module.py"),
    # Markdown targets
    "targets/markdown_node_marked.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/markdown_node_marked_module.js"),
    "targets/markdown_node_markdownit.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/markdown_node_markdownit_module.js"),
    "targets/markdown_node_showdown.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/markdown_node_showdown_module.js"),
    "targets/markdown_python_markdown.py": ("python targets/persistent_wrapper.py", "targets/markdown_python_markdown_module.py"),
    "targets/markdown_python_mistune.py": ("python targets/persistent_wrapper.py", "targets/markdown_python_mistune_module.py"),
    "targets/markdown_python_commonmark.py": ("python targets/persistent_wrapper.py", "targets/markdown_python_commonmark_module.py"),
    "targets/markdown_node_markdownit_safe.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/markdown_node_markdownit_safe_module.js"),
    "targets/markdown_node_marked_gfm.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/markdown_node_marked_gfm_module.js"),
    # GraphQL targets (parse+validate)
    "targets/graphql_node_graphqljs.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/graphql_node_graphqljs_module.js"),
    "targets/graphql_python_graphqlcore.py": ("python targets/persistent_wrapper.py", "targets/graphql_python_graphqlcore_module.py"),
    # GraphQL execution targets (parse+validate+execute with mock resolvers)
    "targets/graphql_node_graphqljs_exec.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper_async.js", "targets/graphql_node_graphqljs_exec_module.js"),
    # DOM Clobbering targets
    "targets/domclobber_dompurify.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/domclobber_dompurify_module.js"),
    "targets/domclobber_jsxss.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/domclobber_jsxss_module.js"),
    "targets/domclobber_sanitize_html.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/domclobber_sanitize_html_module.js"),
    # Class pollution targets
    "targets/class_pollution_merge_target.py": ("python targets/persistent_wrapper.py", "targets/class_pollution_merge_target_module.py"),
    "targets/class_pollution_instrumented_target.py": ("python targets/persistent_wrapper.py", "targets/class_pollution_instrumented_target_module.py"),
    "targets/class_pollution_deepdiff_target.py": ("python targets/persistent_wrapper.py", "targets/class_pollution_deepdiff_target_module.py"),
    "targets/class_pollution_pydantic_target.py": ("python targets/persistent_wrapper.py", "targets/class_pollution_pydantic_target_module.py"),
    "targets/class_pollution_reallib_target.py": ("python targets/persistent_wrapper.py", "targets/class_pollution_reallib_target_module.py"),
    # JS sandbox escape targets
    "node targets/sandbox_vm2_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_vm2_module.js"),
    "node targets/sandbox_ivm_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_ivm_module.js"),
    "node targets/sandbox_ses_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_ses_module.js"),
    "node targets/sandbox_safeeval_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_safeeval_module.js"),
    "node targets/sandbox_vm_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_vm_module.js"),
    "node targets/sandbox_expreval_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_expreval_module.js"),
    "node targets/sandbox_notevil_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_notevil_module.js"),
    "node targets/sandbox_staticeval_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_staticeval_module.js"),
}

# Targets with native persistent mode (binary protocol, no wrapper needed).
# Command format for PersistentTarget: the command itself runs the binary protocol loop.
_NATIVE_PERSISTENT_MAP = {
    "java -cp targets/url_java_uri UrlJavaUri": "java -cp targets/url_java_uri UrlJavaUri --persistent",
    "java -cp targets/url_java_url UrlJavaUrl": "java -cp targets/url_java_url UrlJavaUrl --persistent",
    "targets/url_go_neturl/url_go_neturl.exe": "targets/url_go_neturl/url_go_neturl.exe --persistent",
    "targets/url_go_neturl/url_go_neturl": "targets/url_go_neturl/url_go_neturl --persistent",
    "targets/url_go_net_url/url_go_net_url.exe": "targets/url_go_net_url/url_go_net_url.exe --persistent",
    "targets/url_go_net_url/url_go_net_url": "targets/url_go_net_url/url_go_net_url --persistent",
    "targets/url_rust_url/target/release/url_rust_url.exe": "targets/url_rust_url/target/release/url_rust_url.exe --persistent",
    "targets/url_rust_url/target/release/url_rust_url": "targets/url_rust_url/target/release/url_rust_url --persistent",
    # Python wrapper maps to Go binary persistent mode
    "python targets/url_go_neturl.py": "targets/url_go_neturl/url_go_neturl.exe --persistent",
    # SAML Go target (crewjam/saml)
    "targets/saml_crewjam/saml_crewjam.exe": "targets/saml_crewjam/saml_crewjam.exe --persistent",
    "targets/saml_crewjam/saml_crewjam": "targets/saml_crewjam/saml_crewjam --persistent",
    # SAML Java target (JDK javax.xml.crypto / Xerces)
    "java -cp targets/saml_java_xmldsig SamlJavaXmldsig": "java -cp targets/saml_java_xmldsig SamlJavaXmldsig --persistent",
    # SAML Rust target (quick-xml parser)
    "targets/saml_rust_xmlparser/target/release/saml_rust_xmlparser.exe": "targets/saml_rust_xmlparser/target/release/saml_rust_xmlparser.exe --persistent",
    "targets/saml_rust_xmlparser/target/release/saml_rust_xmlparser": "targets/saml_rust_xmlparser/target/release/saml_rust_xmlparser --persistent",
    # OAuth Go target (fosite)
    "targets/oauth_fosite/oauth_fosite.exe": "targets/oauth_fosite/oauth_fosite.exe --persistent",
    "targets/oauth_fosite/oauth_fosite": "targets/oauth_fosite/oauth_fosite --persistent",
    # GraphQL Java target (graphql-java — parse+validate)
    "java -cp targets/graphql_java GraphqlJava": "java -cp targets/graphql_java/*;targets/graphql_java GraphqlJava --persistent",
    # GraphQL Java execution target (graphql-java — parse+validate+execute)
    "java -cp targets/graphql_java GraphqlJavaExec": "java -cp targets/graphql_java/*;targets/graphql_java GraphqlJavaExec --persistent",
    # JWT Java targets (nimbus-jose-jwt, auth0 java-jwt, jjwt)
    "java -cp targets/jwt_java/*;targets/jwt_java JwtNimbus": "java -cp targets/jwt_java/*;targets/jwt_java JwtNimbus --persistent",
    "java -cp targets/jwt_java/*;targets/jwt_java JwtAuth0": "java -cp targets/jwt_java/*;targets/jwt_java JwtAuth0 --persistent",
    "java -cp targets/jwt_java/*;targets/jwt_java JwtJjwt": "java -cp targets/jwt_java/*;targets/jwt_java JwtJjwt --persistent",
    "java -cp targets/jwt_java/*;targets/jwt_java JwtJose4j": "java -cp targets/jwt_java/*;targets/jwt_java JwtJose4j --persistent",
    # JWT Go targets (go-jose, golang-jwt)
    "targets/jwt_go/jwt_go.exe go_jose": "targets/jwt_go/jwt_go.exe go_jose --persistent",
    "targets/jwt_go/jwt_go.exe golang_jwt": "targets/jwt_go/jwt_go.exe golang_jwt --persistent",
    # Multi-language sanitizer (native binary protocol, no args = persistent)
    "targets/sanitizer_bluemonday.exe": "targets/sanitizer_bluemonday.exe",
    "targets/sanitizer_ammonia.exe": "targets/sanitizer_ammonia.exe",
    "targets/rust-sanitizer/target/release/sanitizer_ammonia.exe": "targets/rust-sanitizer/target/release/sanitizer_ammonia.exe",
    # Java deserialization gadget targets (CC3/CC4/mixed × open/filtered)
    # --add-opens required for Java 17+ module system (reflection on internal fields)
    # java.xml → TemplatesImpl (class_load sink), java.sql.rowset → JdbcRowSetImpl (jndi sink)
    # Classpath uses explicit jars (no wildcards) for Windows compatibility
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath cc3":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath cc3",
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath cc4":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath cc4",
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath cc4 --filter jep290":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath cc4 --filter jep290",
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath mixed":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath mixed",
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath mixed --filter denylist":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath mixed --filter denylist",
    # Docker-based WebLogic 14.1.1.0: DeserB64Wrapper inside real WL container
    # Base64 text protocol avoids Windows binary pipe issues, ~70 exec/s
    # Container ID e3a1ac3f2d14 — update if recreated
    "docker DeserTarget --classpath weblogic":
        "python targets/docker_deser_b64_bridge.py e3a1ac3f2d14 --classpath weblogic",
    "docker DeserTarget --classpath weblogic --filter weblogic":
        "python targets/docker_deser_b64_bridge.py e3a1ac3f2d14 --classpath weblogic --filter weblogic",
    # WebLogic classpath: mixed libs + weblogic.jar + BEA Spring (novel gadget hunting)
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath weblogic":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/weblogic_libs/weblogic.jar;targets/deser_java/weblogic_libs/bea-spring.jar;targets/deser_java/weblogic_libs/javax.transaction_1.0.0.0_1-1.jar;targets/deser_java/weblogic_libs/javax.jms_1.1.1.jar;targets/deser_java/weblogic_libs/com.bea.core.transaction_2.7.1.0.jar;targets/deser_java/weblogic_libs/coherence.jar;targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath weblogic",
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath weblogic --filter denylist":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/weblogic_libs/weblogic.jar;targets/deser_java/weblogic_libs/bea-spring.jar;targets/deser_java/weblogic_libs/javax.transaction_1.0.0.0_1-1.jar;targets/deser_java/weblogic_libs/javax.jms_1.1.1.jar;targets/deser_java/weblogic_libs/com.bea.core.transaction_2.7.1.0.jar;targets/deser_java/weblogic_libs/coherence.jar;targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath weblogic --filter denylist",
    # WebLogic 14.1.1.0 ClassFilter: exact replica of actual WL blacklist (package + class level)
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath weblogic --filter weblogic":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/weblogic_libs/weblogic.jar;targets/deser_java/weblogic_libs/bea-spring.jar;targets/deser_java/weblogic_libs/javax.transaction_1.0.0.0_1-1.jar;targets/deser_java/weblogic_libs/javax.jms_1.1.1.jar;targets/deser_java/weblogic_libs/com.bea.core.transaction_2.7.1.0.jar;targets/deser_java/weblogic_libs/coherence.jar;targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath weblogic --filter weblogic",
    # WildFly shaded gadget discovery: JSTL shaded Xalan + CC3 + CB + Hibernate
    # Shaded classes live in application namespace → no --add-opens needed for them
    # --add-opens still needed for JDK internals used by CC3/CB reflection
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath wildfly":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/wildfly_libs/jakarta.servlet.jsp.jstl-3.0.1-jbossorg-1.jar;targets/deser_java/wildfly_libs/commons-beanutils-1.11.0.jar;targets/deser_java/wildfly_libs/commons-collections-3.2.2.jar;targets/deser_java/wildfly_libs/commons-logging-jboss-logging-1.0.0.Final.jar;targets/deser_java/wildfly_libs/jboss-logging-3.6.1.Final.jar;targets/deser_java/wildfly_libs/hibernate-core-6.6.40.Final.jar;targets/deser_java/wildfly_libs/asm-9.7.1.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java DeserTarget --persistent --classpath wildfly",
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath wildfly --filter wildfly":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/wildfly_libs/jakarta.servlet.jsp.jstl-3.0.1-jbossorg-1.jar;targets/deser_java/wildfly_libs/commons-beanutils-1.11.0.jar;targets/deser_java/wildfly_libs/commons-collections-3.2.2.jar;targets/deser_java/wildfly_libs/commons-logging-jboss-logging-1.0.0.Final.jar;targets/deser_java/wildfly_libs/jboss-logging-3.6.1.Final.jar;targets/deser_java/wildfly_libs/hibernate-core-6.6.40.Final.jar;targets/deser_java/wildfly_libs/asm-9.7.1.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java DeserTarget --persistent --classpath wildfly --filter wildfly",
    # Binary mode: raw .ser bytes → deserialize only (skip IR compilation)
    # -javaagent for JDD-style sink tracking (cmd_exec/jndi/reflection/class_load)
    # WildFly binary mode: shaded Xalan + CC3 + CB + Hibernate on classpath
    "java DeserTarget --binary --classpath wildfly":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.util.concurrent=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/wildfly_libs/jakarta.servlet.jsp.jstl-3.0.1-jbossorg-1.jar;targets/deser_java/wildfly_libs/commons-beanutils-1.11.0.jar;targets/deser_java/wildfly_libs/commons-collections-3.2.2.jar;targets/deser_java/wildfly_libs/commons-logging-jboss-logging-1.0.0.Final.jar;targets/deser_java/wildfly_libs/jboss-logging-3.6.1.Final.jar;targets/deser_java/wildfly_libs/hibernate-core-6.6.40.Final.jar;targets/deser_java/wildfly_libs/asm-9.7.1.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java DeserTarget --persistent --binary --classpath wildfly",
    "java DeserTarget --binary --classpath mixed":
        "java -javaagent:targets/deser_java/deser_agent.jar --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.util.concurrent=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -Dorg.apache.commons.collections.enableUnsafeSerialization=true -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --binary --classpath mixed",
    "java DeserTarget --binary --classpath mixed --filter jep290":
        "java -javaagent:targets/deser_java/deser_agent.jar --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.util.concurrent=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -Dorg.apache.commons.collections.enableUnsafeSerialization=true -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --binary --classpath mixed --filter jep290",
    "java DeserTarget --binary --classpath mixed --filter denylist":
        "java -javaagent:targets/deser_java/deser_agent.jar --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.util.concurrent=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -Dorg.apache.commons.collections.enableUnsafeSerialization=true -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --binary --classpath mixed --filter denylist",
    # ── JNDI ObjectFactory targets (post-8u191 exploitation via local factories) ──
    # Requires Tomcat jars on classpath for BeanFactory, DataSource factories, etc.
    # --add-opens for javax.naming internal access
    # Tomcat 9.0.98 (forceString patched — BeanFactory restricted)
    "java -cp targets/deser_java JndiTarget --classpath tomcat":
        "java --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.naming/javax.naming=ALL-UNNAMED --add-opens java.naming/javax.naming.spi=ALL-UNNAMED -cp targets/deser_java/jndi_libs/tomcat-catalina.jar;targets/deser_java/jndi_libs/tomcat-naming.jar;targets/deser_java/jndi_libs/el-api.jar;targets/deser_java/jndi_libs/tomcat-el.jar;targets/deser_java/jndi_libs/tomcat-dbcp.jar;targets/deser_java/jndi_libs/tomcat-api.jar;targets/deser_java/jndi_libs/tomcat-juli.jar;targets/deser_java/jndi_libs/tomcat-util.jar;targets/deser_java/jndi_libs/annotations-api.jar;targets/deser_java/jndi_libs/h2.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java JndiTarget --persistent",
    # Tomcat 9.0.62 (forceString WORKS — pre-patch, BeanFactory → RCE)
    "java -cp targets/deser_java JndiTarget --classpath tomcat962":
        "java --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.naming/javax.naming=ALL-UNNAMED --add-opens java.naming/javax.naming.spi=ALL-UNNAMED -cp targets/deser_java/jndi_libs/tomcat962-catalina.jar;targets/deser_java/jndi_libs/tomcat962-el-api.jar;targets/deser_java/jndi_libs/tomcat962-el.jar;targets/deser_java/jndi_libs/tomcat962-dbcp.jar;targets/deser_java/jndi_libs/tomcat962-api.jar;targets/deser_java/jndi_libs/tomcat962-juli.jar;targets/deser_java/jndi_libs/tomcat962-util.jar;targets/deser_java/jndi_libs/h2.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java JndiTarget --persistent",
    # Mixed classpath (Tomcat 9.0.62 + extra sinks: Groovy, BeanShell, SnakeYAML)
    "java -cp targets/deser_java JndiTarget --classpath mixed":
        "java --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.naming/javax.naming=ALL-UNNAMED --add-opens java.naming/javax.naming.spi=ALL-UNNAMED -cp targets/deser_java/jndi_libs/tomcat962-catalina.jar;targets/deser_java/jndi_libs/tomcat962-el-api.jar;targets/deser_java/jndi_libs/tomcat962-el.jar;targets/deser_java/jndi_libs/tomcat962-dbcp.jar;targets/deser_java/jndi_libs/tomcat962-api.jar;targets/deser_java/jndi_libs/tomcat962-juli.jar;targets/deser_java/jndi_libs/tomcat962-util.jar;targets/deser_java/jndi_libs/h2.jar;targets/deser_java/jndi_libs/groovy.jar;targets/deser_java/jndi_libs/bsh.jar;targets/deser_java/jndi_libs/snakeyaml.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java JndiTarget --persistent",
    # Full classpath (Tomcat 9.0.62 + WebLogic 14.1.1.0 modules + all gadget JARs)
    # Uses wildcard for WL14 modules (441 JARs, 197MB) — Java resolves at startup
    # NOTE: Tomcat EL JARs listed BEFORE WL wildcard to prevent javax.javaee-api.jar shadow
    "java -cp targets/deser_java JndiTarget --classpath full":
        "java -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.naming/javax.naming=ALL-UNNAMED --add-opens java.naming/javax.naming.spi=ALL-UNNAMED -cp "
        "targets/deser_java/jndi_libs/tomcat962-catalina.jar;targets/deser_java/jndi_libs/tomcat962-el-api.jar;targets/deser_java/jndi_libs/tomcat962-el.jar;targets/deser_java/jndi_libs/tomcat962-dbcp.jar;targets/deser_java/jndi_libs/tomcat962-api.jar;targets/deser_java/jndi_libs/tomcat962-juli.jar;targets/deser_java/jndi_libs/tomcat962-util.jar;"
        "targets/deser_java/weblogic_libs/wl14/*;"
        "targets/deser_java/jndi_libs/h2.jar;targets/deser_java/jndi_libs/hsqldb.jar;targets/deser_java/jndi_libs/groovy.jar;targets/deser_java/jndi_libs/bsh.jar;targets/deser_java/jndi_libs/snakeyaml.jar;"
        "targets/deser_java/jndi_libs/commons-dbcp2.jar;targets/deser_java/jndi_libs/commons-pool2.jar;targets/deser_java/jndi_libs/hikaricp.jar;targets/deser_java/jndi_libs/druid.jar;"
        "targets/deser_java/jndi_libs/c3p0-0.9.5.5.jar;targets/deser_java/jndi_libs/mchange-commons-java-0.2.20.jar;targets/deser_java/jndi_libs/postgresql-42.7.1.jar;targets/deser_java/jndi_libs/mysql-connector-j-8.2.0.jar;"
        "targets/deser_java/jndi_libs/tomcat-jdbc-9.0.62.jar;targets/deser_java/jndi_libs/derby-10.15.2.0.jar;targets/deser_java/jndi_libs/mvel2-2.5.2.Final.jar;"
        "targets/deser_java/jndi_libs/slf4j-api-2.0.9.jar;targets/deser_java/jndi_libs/slf4j-simple-2.0.9.jar;"
        "targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;"
        "targets/deser_java/spring-beans-5.3.31.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;"
        "targets/deser_java/gson-2.11.0.jar;targets/deser_java JndiTarget --persistent",
    # ── JDBC connection-level targets (direct DriverManager + pool lifecycle) ──
    # Uses same jndi_libs/ JARs: JDBC drivers + connection pools + Spring (for PG socketFactory RCE)
    "java -cp targets/deser_java JdbcTarget --classpath full":
        "java -Xmx256m -Xms64m --add-opens java.base/java.lang=ALL-UNNAMED "
        "-cp "
        "targets/deser_java/jndi_libs/h2.jar;targets/deser_java/jndi_libs/hsqldb.jar;"
        "targets/deser_java/jndi_libs/postgresql-42.7.1.jar;targets/deser_java/jndi_libs/mysql-connector-j-8.2.0.jar;"
        "targets/deser_java/jndi_libs/hikaricp.jar;targets/deser_java/jndi_libs/commons-dbcp2.jar;targets/deser_java/jndi_libs/commons-pool2.jar;"
        "targets/deser_java/jndi_libs/c3p0-0.9.5.5.jar;targets/deser_java/jndi_libs/mchange-commons-java-0.2.20.jar;"
        "targets/deser_java/jndi_libs/druid.jar;targets/deser_java/jndi_libs/tomcat-jdbc-9.0.62.jar;"
        "targets/deser_java/jndi_libs/derby-10.15.2.0.jar;"
        "targets/deser_java/jndi_libs/groovy.jar;targets/deser_java/jndi_libs/bsh.jar;targets/deser_java/jndi_libs/snakeyaml.jar;"
        "targets/deser_java/jndi_libs/spring-context-5.3.31.jar;targets/deser_java/jndi_libs/spring-core-5.3.31.jar;"
        "targets/deser_java/jndi_libs/spring-beans-5.3.31.jar;targets/deser_java/jndi_libs/spring-expression-5.3.31.jar;"
        "targets/deser_java/jndi_libs/spring-jcl-5.3.31.jar;"
        "targets/deser_java/jndi_libs/slf4j-api-2.0.9.jar;targets/deser_java/jndi_libs/slf4j-simple-2.0.9.jar;"
        # pyn3rd additions: SQLite, MySQL 5.1 FabricDriver, ModeShape JCR
        "targets/deser_java/jndi_libs/sqlite-jdbc-3.45.1.0.jar;"
        "targets/deser_java/jndi_libs/mysql-connector-java-5.1.49.jar;"
        "targets/deser_java/jndi_libs/modeshape-jdbc-local-5.4.1.Final.jar;"
        # Additional drivers: MariaDB, SQL Server, Oracle
        "targets/deser_java/jndi_libs/mariadb-java-client-3.3.2.jar;"
        "targets/deser_java/jndi_libs/mssql-jdbc-12.4.2.jar;"
        "targets/deser_java/jndi_libs/ojdbc11-23.3.0.jar;"
        "targets/deser_java/gson-2.11.0.jar;targets/deser_java JdbcTarget --persistent",
    # JDBC with embedded drivers only (H2, HSQLDB, Derby — no network needed)
    "java -cp targets/deser_java JdbcTarget --classpath embedded":
        "java -Xmx256m -Xms64m --add-opens java.base/java.lang=ALL-UNNAMED "
        "-cp "
        "targets/deser_java/jndi_libs/h2.jar;targets/deser_java/jndi_libs/hsqldb.jar;"
        "targets/deser_java/jndi_libs/derby-10.15.2.0.jar;"
        "targets/deser_java/jndi_libs/hikaricp.jar;targets/deser_java/jndi_libs/commons-dbcp2.jar;targets/deser_java/jndi_libs/commons-pool2.jar;"
        "targets/deser_java/jndi_libs/c3p0-0.9.5.5.jar;targets/deser_java/jndi_libs/mchange-commons-java-0.2.20.jar;"
        "targets/deser_java/jndi_libs/druid.jar;targets/deser_java/jndi_libs/tomcat-jdbc-9.0.62.jar;"
        "targets/deser_java/jndi_libs/slf4j-api-2.0.9.jar;targets/deser_java/jndi_libs/slf4j-simple-2.0.9.jar;"
        "targets/deser_java/gson-2.11.0.jar;targets/deser_java JdbcTarget --persistent",
}


def to_persistent_cmd(cmd: str, target_coverage: bool = False, lines_only: bool = False) -> str | None:
    """Convert a subprocess target command to a persistent wrapper command.

    Returns None if no persistent mapping exists (caller should fall back
    to ProcessTarget).

    Args:
        target_coverage: If True, append --coverage to Node.js wrapper commands
            to enable V8 function-level coverage collection.

    Example:
        "node targets/sanitizer_dompurify.js {input}"
        -> "node targets/persistent_wrapper.js targets/sanitizer_dompurify_module.js"
        "python targets/url_python_urllib.py {input}"
        -> "python targets/persistent_wrapper.py targets/url_python_urllib_module.py"
        "java -cp targets/url_java_uri UrlJavaUri {input}"
        -> "java -cp targets/url_java_uri UrlJavaUri --persistent"
    """
    # Check native persistent mode first (e.g., Java targets with --persistent flag)
    base_cmd = cmd.replace(" {input}", "").strip()
    # If the command already uses persistent_wrapper or --persistent, use as-is
    if "persistent_wrapper" in base_cmd:
        if base_cmd.startswith("python "):
            base_cmd = f"{sys.executable} {base_cmd[7:]}"
        return base_cmd
    if "--persistent" in base_cmd and base_cmd not in _NATIVE_PERSISTENT_MAP:
        return base_cmd
    if base_cmd in _NATIVE_PERSISTENT_MAP:
        result = _NATIVE_PERSISTENT_MAP[base_cmd]
        # Windows cmd.exe needs backslashes for relative executable paths,
        # but Java handles forward slashes fine and backslashes break -cp globs.
        if sys.platform == "win32" and not result.startswith("java "):
            result = result.replace("/", "\\")
        return result

    for script, (wrapper, module) in _PERSISTENT_MODULE_MAP.items():
        if script in cmd:
            result = f"{wrapper} {module}"
            # Append coverage flag for V8 (Node.js) / settrace (Python)
            if (target_coverage or lines_only) and (
                "persistent_wrapper.js" in wrapper
                or "persistent_wrapper.py" in wrapper
            ):
                result += " --coverage-lines-only" if lines_only else " --coverage"
            # Replace bare "python " with sys.executable to ensure the venv
            # Python is used (subprocess.Popen doesn't activate the venv).
            if result.startswith("python "):
                result = f"{sys.executable} {result[7:]}"
            return result
    # No mapping found — caller should fall back to ProcessTarget
    print(f"Warning: no persistent module mapping for: {cmd}", file=sys.stderr)
    return None


def persistent_timeout_for_cmd(
    cmd: str,
    grammar: str,
    oracle_names: set[str],
    *,
    is_reference: bool = False,
) -> float:
    """Choose a persistent target timeout tuned to the target family."""
    # Docker bridge: each request = docker exec + JVM startup (~1-2s)
    if cmd.startswith("docker "):
        return 15.0

    low_cmd = cmd.lower()

    # WAF differential targets perform real network round-trips against live
    # middleware and can legitimately take longer than the generic non-Java
    # 2s budget, especially under multi-target differential campaigns.
    if "waf_bypass_target.py" in low_cmd:
        return 3.0

    is_java = "java " in cmd or "java.exe " in cmd
    if not is_java:
        return 2.0

    is_jndi = (
        grammar == "jndi"
        or "jnditarget" in low_cmd
        or "jndi" in oracle_names
    )
    if is_jndi:
        return 3.0  # JndiTarget resolve timeout is tiered (500-2000ms)
    is_jdbc = (
        grammar == "jdbc"
        or "jdbctarget" in low_cmd
        or "jdbc" in oracle_names
    )
    if is_jdbc:
        return 5.0
    return 5.0 if is_reference else 3.0

