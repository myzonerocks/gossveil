import{d as e}from"./index-Ce7kJgHE.js";import{t}from"./jsx-runtime-B2FMVfXp.js";import{n}from"./lib-DGkjmMeu.js";function r(r){let i={a:`a`,code:`code`,h2:`h2`,li:`li`,p:`p`,pre:`pre`,span:`span`,strong:`strong`,ul:`ul`,...n(),...r.components};return t(e,{children:[t(i.p,{children:`The Swift, Kotlin and TypeScript packages are thin. Each one opens the same
header, calls the same symbols in the same order, and adds nothing the core
could have done itself.`}),`
`,t(i.p,{children:`So a binding for a language nobody has written yet is a known job, not a
research project. This page covers all of it.`}),`
`,t(i.h2,{id:`what-youre-binding-to`,children:t(i.a,{href:`#what-youre-binding-to`,children:`What you're binding to`})}),`
`,t(i.p,{children:[`One header, `,t(i.code,{children:`gossveil.h`}),`. It includes nothing beyond `,t(i.code,{children:`stddef.h`}),` and
`,t(i.code,{children:`stdint.h`}),`, so any language with a C foreign function interface can reach it.`]}),`
`,t(i.p,{children:[`Three things cross the boundary: pointers with lengths going in, `,t(i.code,{children:`GvBuffer`}),`
cells coming out, and a `,t(i.code,{children:`GvStatus`}),` on every call. There are no handles to
track and no callbacks into your allocator.`]}),`
`,t(i.h2,{id:`step-one-check-the-version`,children:t(i.a,{href:`#step-one-check-the-version`,children:`Step one: check the version`})}),`
`,t(e,{children:t(i.pre,{className:`shiki shiki-themes vitesse-light vitesse-dark`,style:{"--shiki-light":`#393a34`,"--shiki-dark":`#dbd7caee`,"--shiki-light-bg":`#ffffff`,"--shiki-dark-bg":`#121212`},tabIndex:`0`,children:t(i.code,{children:[t(i.span,{className:`line`,children:[t(i.span,{style:{"--shiki-light":`#1E754F`,"--shiki-dark":`#4D9375`},children:`if`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:` (`}),t(i.span,{style:{"--shiki-light":`#59873A`,"--shiki-dark":`#80A665`},children:`gv_abi_version`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`()`}),t(i.span,{style:{"--shiki-light":`#AB5959`,"--shiki-dark":`#CB7676`},children:` !=`}),t(i.span,{style:{"--shiki-light":`#393A34`,"--shiki-dark":`#DBD7CAEE`},children:` GV_ABI_VERSION`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`)`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:` {`})]}),`
`,t(i.span,{className:`line`,children:t(i.span,{style:{"--shiki-light":`#A0ADA0`,"--shiki-dark":`#758575DD`},children:`    /* Refuse. Do not continue and do not degrade. */`})}),`
`,t(i.span,{className:`line`,children:t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`}`})})]})})}),`
`,t(i.p,{children:`A mismatch means the layouts your binding was generated against are not the
ones the library has. Carrying on reads the wrong bytes.`}),`
`,t(i.h2,{id:`step-two-the-memory-rule`,children:t(i.a,{href:`#step-two-the-memory-rule`,children:`Step two: the memory rule`})}),`
`,t(i.p,{children:[`Every byte output is a `,t(i.code,{children:`GvBuffer`}),` the library filled. Free each one exactly
once with `,t(i.code,{children:`gv_free`}),`, passing back the same pointer and length you were given.`]}),`
`,t(e,{children:t(i.pre,{className:`shiki shiki-themes vitesse-light vitesse-dark`,style:{"--shiki-light":`#393a34`,"--shiki-dark":`#dbd7caee`,"--shiki-light-bg":`#ffffff`,"--shiki-dark-bg":`#121212`},tabIndex:`0`,children:t(i.code,{children:[t(i.span,{className:`line`,children:[t(i.span,{style:{"--shiki-light":`#393A34`,"--shiki-dark":`#DBD7CAEE`},children:`GvBuffer out `}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`=`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:` {`}),t(i.span,{style:{"--shiki-light":`#2F798A`,"--shiki-dark":`#4C9A91`},children:`0`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`};`})]}),`
`,t(i.span,{className:`line`,children:[t(i.span,{style:{"--shiki-light":`#1E754F`,"--shiki-dark":`#4D9375`},children:`if`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:` (`}),t(i.span,{style:{"--shiki-light":`#59873A`,"--shiki-dark":`#80A665`},children:`gv_curve_pair`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`(`}),t(i.span,{style:{"--shiki-light":`#AB5959`,"--shiki-dark":`#CB7676`},children:`&`}),t(i.span,{style:{"--shiki-light":`#B07D48`,"--shiki-dark":`#BD976A`},children:`secret`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`,`}),t(i.span,{style:{"--shiki-light":`#AB5959`,"--shiki-dark":`#CB7676`},children:` &`}),t(i.span,{style:{"--shiki-light":`#B07D48`,"--shiki-dark":`#BD976A`},children:`out`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`)`}),t(i.span,{style:{"--shiki-light":`#AB5959`,"--shiki-dark":`#CB7676`},children:` ==`}),t(i.span,{style:{"--shiki-light":`#393A34`,"--shiki-dark":`#DBD7CAEE`},children:` GV_OK`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`)`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:` {`})]}),`
`,t(i.span,{className:`line`,children:t(i.span,{style:{"--shiki-light":`#A0ADA0`,"--shiki-dark":`#758575DD`},children:`    /* use out.ptr, out.len */`})}),`
`,t(i.span,{className:`line`,children:[t(i.span,{style:{"--shiki-light":`#59873A`,"--shiki-dark":`#80A665`},children:`    gv_free`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`(`}),t(i.span,{style:{"--shiki-light":`#B07D48`,"--shiki-dark":`#BD976A`},children:`out`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`.`}),t(i.span,{style:{"--shiki-light":`#B07D48`,"--shiki-dark":`#BD976A`},children:`ptr`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`,`}),t(i.span,{style:{"--shiki-light":`#B07D48`,"--shiki-dark":`#BD976A`},children:` out`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`.`}),t(i.span,{style:{"--shiki-light":`#B07D48`,"--shiki-dark":`#BD976A`},children:`len`}),t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`);`})]}),`
`,t(i.span,{className:`line`,children:t(i.span,{style:{"--shiki-light":`#999999`,"--shiki-dark":`#666666`},children:`}`})})]})})}),`
`,t(i.p,{children:`Two rules follow, and both are easy to get wrong in a managed language:`}),`
`,t(i.ul,{children:[`
`,t(i.li,{children:[t(i.strong,{children:`On a non-zero status every output cell is left empty.`}),` Do not free what
you did not receive, and do not read it either.`]}),`
`,t(i.li,{children:[t(i.strong,{children:`Your allocator did not make these bytes.`}),` Copy into your language's own
memory if you want them to outlive the call, then free the cell.`]}),`
`]}),`
`,t(i.p,{children:[`For hosts that cannot hand the library their own memory, such as wasm,
`,t(i.code,{children:`gv_alloc`}),` provides input memory, freed with the same `,t(i.code,{children:`gv_free`}),`.`]}),`
`,t(i.h2,{id:`step-three-statuses-not-exceptions`,children:t(i.a,{href:`#step-three-statuses-not-exceptions`,children:`Step three: statuses, not exceptions`})}),`
`,t(i.p,{children:[`Nothing throws across the boundary. Map `,t(i.code,{children:`GvStatus`}),` onto your language's error
type and keep the distinctions: an untrusted identity, a missing session and a
replay need different handling, and collapsing them into one error throws away
what the caller needed. See `,t(i.a,{href:`/docs/guides/errors`,children:`errors`}),`.`]}),`
`,t(i.p,{children:[t(i.code,{children:`gv_status_text`}),` gives a readable form for logs.`]}),`
`,t(i.h2,{id:`step-four-records-are-bytes-and-the-caller-owns-them`,children:t(i.a,{href:`#step-four-records-are-bytes-and-the-caller-owns-them`,children:`Step four: records are bytes, and the caller owns them`})}),`
`,t(i.p,{children:`There is no session object. A record goes in, a new record comes out, and the
caller persists it.`}),`
`,t(i.p,{children:`Your binding should make that hard to get wrong. The order is: call, persist
the returned record, then send. A binding that returns the ciphertext and the
new record as one value, which the caller cannot split, makes the dangerous
order impossible to write.`}),`
`,t(i.h2,{id:`step-five-the-stores`,children:t(i.a,{href:`#step-five-the-stores`,children:`Step five: the stores`})}),`
`,t(i.p,{children:`The core calls nothing. Your binding exposes store interfaces to the host
application and passes what they return into the calls that need it, in the
same shapes the three packages use: identity, pre-keys, signed pre-keys,
post-quantum pre-keys, sessions and sender keys.`}),`
`,t(i.p,{children:[`Keep the names the other SDKs use. A developer moving between platforms should
find the same concept under the same word. See `,t(i.a,{href:`/docs/guides/storage`,children:`storage is
yours`}),`.`]}),`
`,t(i.h2,{id:`step-six-no-locking-so-say-so`,children:t(i.a,{href:`#step-six-no-locking-so-say-so`,children:`Step six: no locking, so say so`})}),`
`,t(i.p,{children:`The core does no locking. Two calls advancing one session concurrently is a
lost message, not a crash.`}),`
`,t(i.p,{children:`Document it, and if your language makes it cheap, enforce it: a session type
that can only be used from one task at a time costs nothing and removes the
whole class of bug.`}),`
`,t(i.h2,{id:`step-seven-prove-it-against-the-vectors`,children:t(i.a,{href:`#step-seven-prove-it-against-the-vectors`,children:`Step seven: prove it against the vectors`})}),`
`,t(i.p,{children:`A binding is finished when it agrees with the others, not when it runs.`}),`
`,t(i.p,{children:`Run the conformance vectors through your binding and compare, byte for byte,
against what the core produces:`}),`
`,t(e,{children:t(i.pre,{className:`shiki shiki-themes vitesse-light vitesse-dark`,style:{"--shiki-light":`#393a34`,"--shiki-dark":`#dbd7caee`,"--shiki-light-bg":`#ffffff`,"--shiki-dark-bg":`#121212`},tabIndex:`0`,children:t(i.code,{children:t(i.span,{className:`line`,children:[t(i.span,{style:{"--shiki-light":`#59873A`,"--shiki-dark":`#80A665`},children:`zig`}),t(i.span,{style:{"--shiki-light":`#B56959`,"--shiki-dark":`#C98A7D`},children:` build`}),t(i.span,{style:{"--shiki-light":`#B56959`,"--shiki-dark":`#C98A7D`},children:` conformance`})]})})})}),`
`,t(i.p,{children:`Then do the cross-check that catches the rest: encrypt with your binding,
decrypt with one that ships, and the other way round. A wrong offset, a sign
error or a truncated buffer survives every test except that one.`}),`
`,t(i.h2,{id:`the-shape-of-a-good-binding`,children:t(i.a,{href:`#the-shape-of-a-good-binding`,children:`The shape of a good binding`})}),`
`,t(i.p,{children:`It translates. That's all.`}),`
`,t(i.p,{children:`If your binding caches a record, retries a failed call, or decides whether an
identity is trusted, then an app's behaviour starts depending on which
language it was written in. That's the thing this whole shape exists to avoid.
If you find yourself needing something the core doesn't do, that's a gap in
the core: tell us.`})]})}function i(e={}){let{wrapper:i}={...n(),...e.components};return i?t(i,{...e,children:t(r,{...e})}):r(e)}export{i as default};
//# sourceMappingURL=writing-an-sdk-CUUwkblD.js.map