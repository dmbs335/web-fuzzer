'process' in new Proxy({},{has:(t,p)=>{_report(p);return true}})
