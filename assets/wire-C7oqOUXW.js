import{d as e}from"./index-Ce7kJgHE.js";import{t}from"./jsx-runtime-B2FMVfXp.js";import{n}from"./lib-DGkjmMeu.js";function r(r){let i={a:`a`,code:`code`,h2:`h2`,p:`p`,pre:`pre`,span:`span`,...n(),...r.components};return t(e,{children:[t(i.p,{children:`Key encodings, record layouts, message framing and key schedules are the same
on every platform, because there's only one implementation of them.`}),`
`,t(i.p,{children:`That's not a convention the SDKs agree to follow. There's one core, and the
packages are translation layers over it.`}),`
`,t(i.h2,{id:`how-it-is-held`,children:t(i.a,{href:`#how-it-is-held`,children:`How it is held`})}),`
`,t(i.p,{children:`Frozen wire vectors, recorded by this project's own tooling, are replayed on
every build. If a change alters an encoding, the conformance step fails and it never ships,
so nobody's existing sessions break.`}),`
`,t(e,{children:t(i.pre,{className:`shiki shiki-themes vitesse-light vitesse-dark`,style:{"--shiki-light":`#393a34`,"--shiki-dark":`#dbd7caee`,"--shiki-light-bg":`#ffffff`,"--shiki-dark-bg":`#121212`},tabIndex:`0`,children:t(i.code,{children:t(i.span,{className:`line`,children:[t(i.span,{style:{"--shiki-light":`#59873A`,"--shiki-dark":`#80A665`},children:`zig`}),t(i.span,{style:{"--shiki-light":`#B56959`,"--shiki-dark":`#C98A7D`},children:` build`}),t(i.span,{style:{"--shiki-light":`#B56959`,"--shiki-dark":`#C98A7D`},children:` conformance`})]})})})}),`
`,t(i.h2,{id:`what-this-buys-you`,children:t(i.a,{href:`#what-this-buys-you`,children:`What this buys you`})}),`
`,t(i.p,{children:`A session record written by the Swift package opens in the TypeScript one. A
message encrypted on Android decrypts in a browser. A user moving between
their phone and the web keeps their conversations, because nothing about the
cryptography or the bytes changed on the way.`}),`
`,t(i.p,{children:`It also means your server doesn't need to know which client sent what. The
bytes are the bytes.`}),`
`,t(i.h2,{id:`versions-on-the-wire`,children:t(i.a,{href:`#versions-on-the-wire`,children:`Versions on the wire`})}),`
`,t(i.p,{children:[`A message carries a version. Older than this build understands gives `,t(i.code,{children:`GV_LEGACY_VERSION`}),`, newer gives
`,t(i.code,{children:`GV_UNKNOWN_VERSION`}),`. Both are answers you can act on, and neither crashes.`]}),`
`,t(i.p,{children:`Keep them distinct in your UI: one means the other end should update, the
other means this end should.`}),`
`,t(i.h2,{id:`the-abi-version`,children:t(i.a,{href:`#the-abi-version`,children:`The ABI version`})}),`
`,t(i.p,{children:[t(i.code,{children:`gv_abi_version`}),` reports the version of the C surface. A binding compares it
and refuses a library it was not built against; see `,t(i.a,{href:`/docs/binding/abi-reference`,children:`the ABI
reference`}),`.`]}),`
`,t(i.p,{children:`That's a different thing from the wire version, and the two move
independently. The ABI is between your binding and the library. The wire is
between two people's devices.`})]})}function i(e={}){let{wrapper:i}={...n(),...e.components};return i?t(i,{...e,children:t(r,{...e})}):r(e)}export{i as default};
//# sourceMappingURL=wire-C7oqOUXW.js.map