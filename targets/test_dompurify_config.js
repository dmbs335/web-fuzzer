"use strict";
const { JSDOM } = require("jsdom");

const window = new JSDOM("").window;
const DOMPurify = require("dompurify")(window);

const pkg = require("./node_modules/dompurify/package.json");
console.log("DOMPurify version:", pkg.version);
console.log("");

const tests = [
  ["Default @import js:", '<svg><style>@import "javascript:alert(1)"</style></svg>', {}],
  ["FORCE_BODY:", '<svg><style>@import "javascript:alert(1)"</style></svg>', { FORCE_BODY: true }],
  ["FORBID style:", '<svg><style>@import "javascript:alert(1)"</style></svg>', { FORBID_TAGS: ["style"] }],
  ["SAFE_FOR_TEMPLATES:", '<svg><style>@import "javascript:alert(1)"</style></svg>', { SAFE_FOR_TEMPLATES: true }],
  ["Expression:", "<svg><style>*{x:expression(alert(1))}</style></svg>", {}],
  ["External import:", '<svg><style>@import "//evil.com/xss.css"</style></svg>', {}],
  ["-moz-binding:", "<svg><style>*{-moz-binding:url(javascript:alert(1))}</style></svg>", {}],
  ["behavior:", "<svg><style>*{behavior:url(#default#userData)}</style></svg>", {}],
  ["background url js:", "<svg><style>*{background:url(javascript:alert(1))}</style></svg>", {}],
];

tests.forEach(([label, input, config]) => {
  console.log(label, DOMPurify.sanitize(input, config));
});
