*DOMAIN
webtob

*NODE
webtob1         WEBTOBDIR="$WEBTOB_HOME",
                SHMKEY = 54000,
                DOCROOT="docs",
                PORT = "80",
                HTH = 1,
                HOSTNAME = "0.0.0.0",
                NODENAME = "webtob",
                ServiceOrder = "uri,ext",
                JSVPORT = 9900,
                IPCPERM = 0777,
                LOGGING = "acc_log",
                ERRORLOG = "err_log",
                SYSLOG = "syslog"

*HTH_THREAD
hth_worker
                WorkerThreads = 8

*SVRGROUP
htmlg           SVRTYPE = HTML
jsvg            SVRTYPE = JSV

*SERVER
# JSV connector to JEUS — registration-id must match JEUS webtob-connector
MyGroup         SVGNAME = jsvg,
                MinProc = 2,
                MaxProc = 100,
                ASQCount = 1

*URI
# Forward all requests to JEUS via JSV
uri_all         Uri = "/",
                Svrtype = JSV

*LOGGING
syslog          Format = "SYSLOG",
                FileName = "/root/webtob/log/system.log_%M%%D%%Y%",
                Option = "sync"
acc_log         Format = "COMBINED",
                FileName = "/root/webtob/log/access_%Y%%M%%D%.log",
                Option = "sync"
err_log         Format = "ERROR",
                FileName = "/root/webtob/log/error_%Y%%M%%D%.log",
                Option = "sync"

*EXT
htm             MimeType = "text/html", SvrType = HTML
html            MimeType = "text/html", SvrType = HTML
jsp             MimeType = "application/jsp", SvrType = JSV
css             MimeType = "text/css", SvrType = HTML
js              MimeType = "application/x-javascript", SvrType = HTML
txt             MimeType = "text/plain", SvrType = HTML
png             MimeType = "image/png", SvrType = HTML
jpg             MimeType = "image/jpeg", SvrType = HTML
gif             MimeType = "image/gif", SvrType = HTML
ico             MimeType = "image/x-icon", SvrType = HTML
xml             MimeType = "application/xml", SvrType = HTML
json            MimeType = "application/json", SvrType = HTML
