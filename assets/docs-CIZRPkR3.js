import{d as e}from"./index-Ce7kJgHE.js";import{t}from"./jsx-runtime-B2FMVfXp.js";import{n}from"./lib-DGkjmMeu.js";function r(r){let i={a:`a`,h2:`h2`,li:`li`,ol:`ol`,p:`p`,strong:`strong`,table:`table`,tbody:`tbody`,td:`td`,th:`th`,thead:`thead`,tr:`tr`,...n(),...r.components},{Tip:o}=i;return o||a(`Tip`,!0),t(e,{children:[t(i.p,{children:`gossveil is end-to-end encryption for messaging apps. You get forward-secret
sessions with a post-quantum handshake, group messaging, sealed envelopes and
safety numbers, and your app keeps its own storage.`}),`
`,t(i.p,{children:`The protocol lives in one Zig core with no runtime dependencies. Over it sits a
C ABI, and over that three thin packages: Swift, Kotlin and TypeScript. They
share one operation contract, so the same concept has the same name everywhere
and a record written on one platform opens on another.`}),`
`,t(o,{children:t(i.p,{children:[`Straight to an SDK: `,t(i.a,{href:`/docs/sdk/swift`,children:`Swift`}),`, `,t(i.a,{href:`/docs/sdk/kotlin`,children:`Kotlin`}),`,
`,t(i.a,{href:`/docs/sdk/typescript`,children:`TypeScript`}),`, `,t(i.a,{href:`/docs/sdk/c`,children:`C`}),`.`]})}),`
`,t(i.h2,{id:`where-to-start`,children:t(i.a,{href:`#where-to-start`,children:`Where to start`})}),`
`,t(i.table,{children:[t(i.thead,{children:t(i.tr,{children:[t(i.th,{children:`If you're`}),t(i.th,{children:`Start here`})]})}),t(i.tbody,{children:[t(i.tr,{children:[t(i.td,{children:`Adding it to an app`}),t(i.td,{children:[t(i.a,{href:`/docs/install/sdks`,children:`Add an SDK`}),`, then your language`]})]}),t(i.tr,{children:[t(i.td,{children:`Writing your first session`}),t(i.td,{children:t(i.a,{href:`/docs/start/quickstart`,children:`Quickstart`})})]}),t(i.tr,{children:[t(i.td,{children:`Sending to a group`}),t(i.td,{children:t(i.a,{href:`/docs/concepts/circles`,children:`Circles`})})]}),t(i.tr,{children:[t(i.td,{children:`Hiding who sent a message`}),t(i.td,{children:t(i.a,{href:`/docs/concepts/envelopes`,children:`Envelopes`})})]}),t(i.tr,{children:[t(i.td,{children:`Deciding where keys live`}),t(i.td,{children:t(i.a,{href:`/docs/guides/storage`,children:`Storage is yours`})})]}),t(i.tr,{children:[t(i.td,{children:`Binding another language`}),t(i.td,{children:t(i.a,{href:`/docs/binding/writing-an-sdk`,children:`Writing your own SDK`})})]})]})]}),`
`,t(i.h2,{id:`what-the-library-covers`,children:t(i.a,{href:`#what-the-library-covers`,children:`What the library covers`})}),`
`,t(i.table,{children:[t(i.thead,{children:t(i.tr,{children:[t(i.th,{children:`Area`}),t(i.th,{children:`What it covers`})]})}),t(i.tbody,{children:[t(i.tr,{children:[t(i.td,{children:`Sessions`}),t(i.td,{children:`Published key bundles, the handshake, a forward-secret ratchet with skipped-key recovery, session records with archived states, replay rejection`})]}),t(i.tr,{children:[t(i.td,{children:`Post-quantum`}),t(i.td,{children:`A post-quantum key in every bundle and a sparse post-quantum ratchet inside every session`})]}),t(i.tr,{children:[t(i.td,{children:`Circles`}),t(i.td,{children:`Sender-key distribution, group encrypt and decrypt, out-of-order delivery`})]}),t(i.tr,{children:[t(i.td,{children:`Envelopes`}),t(i.td,{children:`Server and sender certificates, envelopes for one recipient and for many`})]}),t(i.tr,{children:[t(i.td,{children:`Identity`}),t(i.td,{children:`Curve25519 keys and signatures, identity pairs, alternate-identity proofs`})]}),t(i.tr,{children:[t(i.td,{children:`Safety numbers`}),t(i.td,{children:`The iterated fingerprint, its sixty-digit form and its scannable form`})]}),t(i.tr,{children:[t(i.td,{children:`Handles`}),t(i.td,{children:`Hashing, zero-knowledge proofs of ownership, links, candidates`})]}),t(i.tr,{children:[t(i.td,{children:`The vault`}),t(i.td,{children:`Entropy pool, backup key, backup id, media ids and media keys`})]}),t(i.tr,{children:[t(i.td,{children:`Primitives`}),t(i.td,{children:`HKDF, AES-256-GCM-SIV, chunked MACs, random bytes, content framing`})]})]})]}),`
`,t(i.h2,{id:`what-it-doesnt-do`,children:t(i.a,{href:`#what-it-doesnt-do`,children:`What it doesn't do`})}),`
`,t(i.p,{children:`Anything that talks to a particular service. Registration, contact discovery,
key backup enclaves, key transparency, backup-file validation and credential
issuance all belong to your app and your backend.`}),`
`,t(i.p,{children:`gossveil handles the cryptography and the wire format. Every policy decision
is yours.`}),`
`,t(i.h2,{id:`three-things-to-know-first`,children:t(i.a,{href:`#three-things-to-know-first`,children:`Three things to know first`})}),`
`,t(i.ol,{children:[`
`,t(i.li,{children:[t(i.strong,{children:`You own the storage.`}),` You implement the stores against your own
database, in your own language. See `,t(i.a,{href:`/docs/guides/storage`,children:`storage is
yours`}),`.`]}),`
`,t(i.li,{children:[t(i.strong,{children:`Records are bytes.`}),` Sessions, keys and group state all serialise to
bytes you persist and hand back. Nothing holds a connection or a file.`]}),`
`,t(i.li,{children:[t(i.strong,{children:`One wire everywhere.`}),` Key encodings, record layouts and message framing
are checked against frozen vectors on every build. See `,t(i.a,{href:`/docs/guides/wire`,children:`one wire, every
platform`}),`.`]}),`
`]})]})}function i(e={}){let{wrapper:i}={...n(),...e.components};return i?t(i,{...e,children:t(r,{...e})}):r(e)}function a(e,t){throw Error(`Expected `+(t?`component`:`object`)+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}export{i as default};
//# sourceMappingURL=docs-CIZRPkR3.js.map