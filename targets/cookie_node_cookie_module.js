/**
 * Persistent module — cookie (npm).
 *
 * Exports process(input) for use with persistent_wrapper.js.
 */
"use strict";

const cookie = require("cookie");

function process(input) {
  const data = input.trim();
  if (!data) {
    return { output: "", exitCode: 1 };
  }

  try {
    const parts = data.split(/;\s*/);
    if (parts.length === 0 || !parts[0].includes("=")) {
      return { output: "", exitCode: 1 };
    }

    const eqIdx = parts[0].indexOf("=");
    const name = parts[0].substring(0, eqIdx).trim();
    const value = parts[0].substring(eqIdx + 1).trim();

    if (!name) {
      return { output: "", exitCode: 1 };
    }

    const attrs = {
      domain: "",
      path: "",
      expires: "",
      max_age: "",
      secure: false,
      httponly: false,
      samesite: "",
    };

    for (let i = 1; i < parts.length; i++) {
      const part = parts[i].trim();
      if (!part) continue;
      const attrEq = part.indexOf("=");
      let attrName, attrValue;
      if (attrEq === -1) {
        attrName = part.toLowerCase();
        attrValue = "";
      } else {
        attrName = part.substring(0, attrEq).trim().toLowerCase();
        attrValue = part.substring(attrEq + 1).trim();
      }
      switch (attrName) {
        case "domain": attrs.domain = attrValue; break;
        case "path": attrs.path = attrValue; break;
        case "expires":
          try {
            const d = new Date(attrValue);
            attrs.expires = isNaN(d.getTime()) ? attrValue : d.toUTCString();
          } catch (_) { attrs.expires = attrValue; }
          break;
        case "max-age": attrs.max_age = attrValue; break;
        case "secure": attrs.secure = true; break;
        case "httponly": attrs.httponly = true; break;
        case "samesite": attrs.samesite = attrValue; break;
      }
    }

    let libParsed;
    try {
      libParsed = cookie.parse(name + "=" + value);
    } catch (_) {
      libParsed = {};
    }
    const libValue = libParsed[name] !== undefined ? libParsed[name] : value;

    const result = JSON.stringify({
      name: name,
      value: libValue,
      domain: attrs.domain,
      path: attrs.path,
      expires: attrs.expires,
      max_age: attrs.max_age,
      secure: attrs.secure,
      httponly: attrs.httponly,
      samesite: attrs.samesite,
    });
    return { output: result, exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
}

module.exports = { process };
