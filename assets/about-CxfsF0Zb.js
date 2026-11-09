import{d as e}from"./index-Ce7kJgHE.js";import{t}from"./jsx-runtime-B2FMVfXp.js";import{n}from"./lib-DGkjmMeu.js";function r(r){let i={a:`a`,h2:`h2`,p:`p`,...n(),...r.components};return t(e,{children:[t(i.p,{children:`Encrypting a message is the easy part. What makes end-to-end encryption hard
in a real app is everything around it: publishing keys so a stranger can start
a conversation, keeping forward secrecy when messages arrive out of order,
adding someone to a group without re-encrypting for everyone, hiding who sent
what from your own servers, and letting two people check they're talking to
each other and not to somebody in between.`}),`
`,t(i.p,{children:`gossveil is that machinery. It's a library you call, not a service you depend
on.`}),`
`,t(i.h2,{id:`why-one-core`,children:t(i.a,{href:`#why-one-core`,children:`Why one core`})}),`
`,t(i.p,{children:`An app that ships on iOS, Android and the web has three chances to get the
same protocol subtly wrong. A ratchet that drops a skipped key on one platform
and keeps it on another isn't one protocol, it's two, and the bug shows up as
"messages sometimes fail to decrypt" months later.`}),`
`,t(i.p,{children:`So the protocol lives in one place, in Zig, with no runtime and no garbage
collector. The SDKs just translate. If one of them started making its own
decisions, your app would behave differently on iOS than on Android, and
you'd have no idea which one was right.`}),`
`,t(i.h2,{id:`why-post-quantum-now`,children:t(i.a,{href:`#why-post-quantum-now`,children:`Why post-quantum now`})}),`
`,t(i.p,{children:`An adversary who records your traffic today can keep it until a quantum
computer can open it. That's not a future problem for a message sent now, so
the handshake carries a post-quantum key from the first message and the
session keeps a sparse post-quantum ratchet alongside the classical one.`}),`
`,t(i.p,{children:`You don't turn it on. There's no second code path to keep in step.`}),`
`,t(i.h2,{id:`why-your-storage-stays-yours`,children:t(i.a,{href:`#why-your-storage-stays-yours`,children:`Why your storage stays yours`})}),`
`,t(i.p,{children:`Keys belong in whatever your app already uses: a Keychain, an encrypted
database, a file you manage. A library that brought its own storage would be making a security decision for
you, and it would be the wrong one for somebody.`}),`
`,t(i.p,{children:[`So you implement a handful of store interfaces and gossveil calls them. It
never opens a file or a connection of its own. See `,t(i.a,{href:`/docs/guides/storage`,children:`storage is
yours`}),`.`]}),`
`,t(i.h2,{id:`why-the-boundary-stops-where-it-does`,children:t(i.a,{href:`#why-the-boundary-stops-where-it-does`,children:`Why the boundary stops where it does`})}),`
`,t(i.p,{children:`Registration, contact discovery, key transparency and backup enclaves all need
a server with opinions. Those opinions are yours, and they differ for every
product.`}),`
`,t(i.p,{children:`We'd have to guess your architecture to include them. Leaving them out keeps
gossveil the same for everybody, and the part on top stays yours.`})]})}function i(e={}){let{wrapper:i}={...n(),...e.components};return i?t(i,{...e,children:t(r,{...e})}):r(e)}export{i as default};
//# sourceMappingURL=about-CxfsF0Zb.js.map