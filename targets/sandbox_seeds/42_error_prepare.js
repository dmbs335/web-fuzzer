var _orig = Error.prepareStackTrace; Error.prepareStackTrace = function(e,s){return s}; try{null.f()}catch(e){_report(e.stack)}
