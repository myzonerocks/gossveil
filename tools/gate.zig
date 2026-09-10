//! The source gate, run by the hooks and by CI:
//!
//!   --staged            pre-commit: staged files through every check
//!   --tree              CI and local: every tracked file through every check
//!   --commit-msg <file> commit-msg hook: the message being written
//!   --log <range>       CI: commit messages in a rev range
//!   --diff <range>      CI: added lines in a rev range, for comment hygiene
//!   --pr-body <file>    CI: a pull request body, for provenance and shape
//!
//! Inbound: private notes, build products, archives and binaries never enter
//! history. Provenance: no tool or model attribution anywhere. Names: no other
//! implementation, its organisation or its licence is named in the tree; the
//! terms are stored rot13 so this file passes itself. Prose: no long dashes,
//! comment blocks of four lines at most.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const max_file_scan_bytes: usize = 1 << 20;
const max_staged_file_bytes: u64 = 4 << 20;
const max_comment_block_lines: usize = 4;

const forbidden_prefixes = [_][]const u8{ "docs/private/", "zig-out/", ".zig-cache/", ".local/", ".build/" };
const forbidden_segments = [_][]const u8{ "node_modules", "DerivedData", ".gradle", "dist" };
const forbidden_extensions = [_][]const u8{ ".zip", ".tar", ".tgz", ".xz", ".gz", ".7z", ".a", ".so", ".dylib", ".dll", ".o", ".aar", ".apk", ".ipa", ".wasm", ".xcframework", ".jpg", ".jpeg", ".png", ".webp" };
const allowed_binaries = [_][]const u8{"sdk/kotlin/gradle/wrapper/gradle-wrapper.jar"};

// Assembled from halves so this file never contains the strings it bans.
const banned_tokens = [_][]const u8{
    "cla" ++ "ude",       "anthro" ++ "pic",      "chat" ++ "gpt",           "open" ++ "ai",
    "copi" ++ "lot",      "gem" ++ "ini",         "deep" ++ "seek",          "co-auth" ++ "ored-by",
    "generated " ++ "with", "ai-gen" ++ "erated",
};
const banned_message_tokens = [_][]const u8{
    "cur" ++ "sor",       "cod" ++ "ex",          "winds" ++ "urf",          "qw" ++ "en",
    "mist" ++ "ral",      "openro" ++ "uter",     "perple" ++ "xity",        "assisted" ++ "-by",
    "generated" ++ "-by", "co-devel" ++ "oped-by", "language " ++ "model",  "ai " ++ "agent",
    "coding " ++ "agent", "coding " ++ "assistant",
};

// rot13; decoded at start. Other implementations, their organisations,
// their package names, their licence, and machine home paths.
const encoded_names = [_][]const u8{
    "betl.fvtany",   "fvtanycncc",  "fvtany.bet",   "yvofvtany-pyvrag",  "yvofvtany-naqebvq",
    "yvofvtany-cebgbpby", "yvofvtany-arg", "trgznncc", "fvtany-jnfz",  "juvfcrefflfgrzf",
    "bcra juvfcre",  "ntcy",        "tcy-3",        "tcyi3",             "tbffnv",
    "/hfref/",       "/ubzr/",
};
// The one place a name may appear: the README's single line of credit.
const name_exempt_paths = [_][]const u8{"README.md"};
const name_exempt_terms = [_][]const u8{};

const Hit = struct { text: []const u8 };

const Gate = struct {
    arena: Allocator,
    io: Io,
    names: [][]const u8,
    hits: std.ArrayList([]const u8) = .empty,

    fn flag(g: *Gate, comptime fmt: []const u8, args: anytype) !void {
        try g.hits.append(g.arena, try std.fmt.allocPrint(g.arena, fmt, args));
    }

    fn git(g: *Gate, argv: []const []const u8) ![]u8 {
        const res = std.process.run(g.arena, g.io, .{ .argv = argv, .stdout_limit = .limited(64 << 20) }) catch |err| {
            std.debug.print("gate: cannot run {s}: {t}\n", .{ argv[0], err });
            return error.GitUnavailable;
        };
        switch (res.term) {
            .exited => |code| if (code != 0) {
                std.debug.print("gate: {s} exited {d}: {s}\n", .{ argv[1], code, res.stderr });
                return error.GitFailed;
            },
            else => return error.GitFailed,
        }
        return res.stdout;
    }

    fn lines(text: []const u8) std.mem.SplitIterator(u8, .scalar) {
        return std.mem.splitScalar(u8, text, '\n');
    }

    fn lower(g: *Gate, text: []const u8) ![]u8 {
        const out = try g.arena.alloc(u8, text.len);
        for (text, 0..) |ch, i| out[i] = std.ascii.toLower(ch);
        return out;
    }

    fn isExemptPath(path: []const u8) bool {
        for (name_exempt_paths) |p| if (std.mem.eql(u8, path, p)) return true;
        return false;
    }

    fn checkPath(g: *Gate, path: []const u8) !void {
        for (forbidden_prefixes) |p| if (std.mem.startsWith(u8, path, p)) return g.flag("inbound: '{s}' is under '{s}', which never enters history", .{ path, p });
        var it = std.mem.splitScalar(u8, path, '/');
        while (it.next()) |seg| {
            for (forbidden_segments) |s| if (std.mem.eql(u8, seg, s)) return g.flag("inbound: '{s}' carries the build segment '{s}'", .{ path, s });
        }
        for (allowed_binaries) |a| if (std.mem.eql(u8, path, a)) return;
        for (forbidden_extensions) |e| if (std.mem.endsWith(u8, path, e)) return g.flag("inbound: '{s}' is a fetched or built artifact ({s})", .{ path, e });
    }

    fn checkText(g: *Gate, context: []const u8, text: []const u8, path: ?[]const u8) !void {
        const low = try g.lower(text);
        for (banned_tokens) |tok| if (std.mem.indexOf(u8, low, tok) != null) try g.flag("provenance: {s} contains '{s}'", .{ context, tok });
        const exempt = if (path) |p| isExemptPath(p) else false;
        if (!exempt) {
            var line_no: usize = 1;
            var it = lines(low);
            while (it.next()) |line| : (line_no += 1) {
                for (g.names) |name| if (std.mem.indexOf(u8, line, name) != null) try g.flag("names: {s}:{d} names '{s}'", .{ context, line_no, name });
            }
        }
    }

    fn checkMessage(g: *Gate, context: []const u8, text: []const u8) !void {
        try g.checkText(context, text, null);
        const low = try g.lower(text);
        for (banned_message_tokens) |tok| if (std.mem.indexOf(u8, low, tok) != null) try g.flag("provenance: {s} contains '{s}'", .{ context, tok });
        try g.checkDashes(context, text);
    }

    // The em dash is always the tell; the en dash is allowed only between digits.
    fn checkDashes(g: *Gate, context: []const u8, text: []const u8) !void {
        var i: usize = 0;
        while (i + 2 < text.len) : (i += 1) {
            if (text[i] != 0xE2 or text[i + 1] != 0x80) continue;
            const kind = text[i + 2];
            if (kind == 0x94) return g.flag("long-dash: {s} uses an em dash; use a plain hyphen or restructure the sentence", .{context});
            if (kind == 0x93) {
                const before = i > 0 and std.ascii.isDigit(text[i - 1]);
                const after = i + 3 < text.len and std.ascii.isDigit(text[i + 3]);
                if (!(before and after)) return g.flag("long-dash: {s} uses an en dash outside a number range", .{context});
            }
        }
    }

    fn isProse(path: []const u8) bool {
        return std.mem.endsWith(u8, path, ".md");
    }

    fn checkFile(g: *Gate, path: []const u8) !void {
        try g.checkPath(path);
        const data = Io.Dir.cwd().readFileAlloc(g.io, path, g.arena, .limited(max_file_scan_bytes)) catch return;
        for (data[0..@min(data.len, 512)]) |ch| if (ch == 0) return;
        try g.checkText(path, data, path);
        if (isProse(path)) try g.checkDashes(path, data);
        try g.checkCommentBlocks(path, data);
    }

    // A run of consecutive comment lines past four is an essay; say it shorter.
    fn checkCommentBlocks(g: *Gate, path: []const u8, data: []const u8) !void {
        const marker: []const u8 = if (std.mem.endsWith(u8, path, ".zig")) "//" else if (std.mem.endsWith(u8, path, ".swift") or std.mem.endsWith(u8, path, ".kt") or std.mem.endsWith(u8, path, ".ts") or std.mem.endsWith(u8, path, ".java") or std.mem.endsWith(u8, path, ".c") or std.mem.endsWith(u8, path, ".h")) "//" else return;
        var run: usize = 0;
        var first: []const u8 = "";
        var it = lines(data);
        while (it.next()) |raw| {
            const line = std.mem.trimStart(u8, raw, " \t");
            const is_comment = std.mem.startsWith(u8, line, marker) and !std.mem.startsWith(u8, line, "//!") and !std.mem.startsWith(u8, line, "///");
            if (is_comment) {
                if (run == 0) first = line;
                run += 1;
                continue;
            }
            if (run > max_comment_block_lines) try g.flag("comment-hygiene: '{s}' has a {d}-line comment block starting '{s}'; four lines at most", .{ path, run, first });
            run = 0;
        }
        if (run > max_comment_block_lines) try g.flag("comment-hygiene: '{s}' ends with a {d}-line comment block; four lines at most", .{ path, run });
    }

    fn trackedPaths(g: *Gate) ![][]const u8 {
        return g.splitZ(try g.git(&.{ "git", "ls-files", "-z" }));
    }

    fn stagedPaths(g: *Gate) ![][]const u8 {
        return g.splitZ(try g.git(&.{ "git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z" }));
    }

    fn splitZ(g: *Gate, out: []const u8) ![][]const u8 {
        var list: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, out, 0);
        while (it.next()) |p| if (p.len > 0) try list.append(g.arena, p);
        return list.items;
    }

    /// A range is one argument here and several to git: the first push of a branch asks for
    /// "<sha> --not --remotes=origin", which git reads as one ambiguous revision unless it is
    /// split back into the words it was written as.
    fn rangeArgv(g: *Gate, head: []const []const u8, range: []const u8) ![]const []const u8 {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(g.arena, head);
        var words = std.mem.tokenizeAny(u8, range, " \t");
        while (words.next()) |word| try argv.append(g.arena, word);
        return argv.items;
    }

    fn checkLogRange(g: *Gate, range: []const u8) !void {
        const out = try g.git(try g.rangeArgv(&.{ "git", "log", "--format=%H%x1f%B%x00" }, range));
        var it = std.mem.splitScalar(u8, out, 0);
        while (it.next()) |entry| {
            if (entry.len == 0) continue;
            const sep = std.mem.indexOfScalar(u8, entry, 0x1f) orelse continue;
            const context = try std.fmt.allocPrint(g.arena, "commit {s}", .{entry[0..@min(sep, 12)]});
            try g.checkMessage(context, entry[sep + 1 ..]);
        }
    }

    fn checkDiffRange(g: *Gate, range: []const u8) !void {
        const out = try g.git(try g.rangeArgv(&.{ "git", "diff", "--diff-filter=ACMR", "-U0" }, range));
        var path: []const u8 = "";
        var run: usize = 0;
        var shipped: ?[]const u8 = null;
        var logged = false;
        var it = lines(out);
        while (it.next()) |line| {
            if (std.mem.startsWith(u8, line, "+++ b/")) {
                path = line[6..];
                run = 0;
                if (shipped == null and shipsToUsers(path)) shipped = path;
                if (std.mem.eql(u8, path, changelog_path)) logged = true;
                continue;
            }
            if (line.len > 0 and line[0] == '+' and !std.mem.startsWith(u8, line, "+++")) {
                const body = std.mem.trimStart(u8, line[1..], " \t");
                if (std.mem.startsWith(u8, body, "//") and !std.mem.startsWith(u8, body, "///") and !std.mem.startsWith(u8, body, "//!")) {
                    run += 1;
                    if (run == max_comment_block_lines + 1) try g.flag("comment-hygiene: '{s}' adds a comment block longer than {d} lines", .{ path, max_comment_block_lines });
                    continue;
                }
                try g.checkText(path, line[1..], path);
            }
            run = 0;
        }
        if (shipped) |first| if (!logged) try g.flag("changelog: '{s}' changes what ships without a line under Unreleased in {s}", .{ first, changelog_path });
    }

    // A pull request body says what changed and the one thing a reader would not
    // guess: no headers, no checklists, no tool names, no long dashes.
    fn checkPrBody(g: *Gate, text: []const u8) !void {
        try g.checkMessage("the pull request body", text);
        var it = lines(text);
        while (it.next()) |raw| {
            const line = std.mem.trimStart(u8, raw, " \t");
            if (std.mem.startsWith(u8, line, "#")) try g.flag("pr-body: markdown headers are not part of the shape ('{s}')", .{line});
            if (std.mem.startsWith(u8, line, "- [ ]") or std.mem.startsWith(u8, line, "- [x]")) try g.flag("pr-body: checklists are not part of the shape", .{});
        }
        if (std.mem.trim(u8, text, " \t\r\n").len == 0) try g.flag("pr-body: the body is empty", .{});
    }
};

const changelog_path = "CHANGELOG.md";
const shipped_roots = [_][]const u8{ "core/", "abi/", "include/", "sdk/", "conformance/vectors/" };

/// Whether a change to this path reaches a user of the library.
fn shipsToUsers(path: []const u8) bool {
    for (shipped_roots) |root| if (std.mem.startsWith(u8, path, root)) return true;
    return false;
}

test "only shipped paths ask for a changelog line" {
    try std.testing.expect(shipsToUsers("core/keys/curve.zig"));
    try std.testing.expect(shipsToUsers("sdk/ts/src/api.ts"));
    try std.testing.expect(!shipsToUsers("docs/DESIGN.md"));
    try std.testing.expect(!shipsToUsers("tools/gate.zig"));
    try std.testing.expect(!shipsToUsers("conformance/conform.zig"));
}

fn rot13(allocator: Allocator, text: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, text.len);
    for (text, 0..) |ch, i| {
        out[i] = switch (ch) {
            'a'...'m', 'A'...'M' => ch + 13,
            'n'...'z', 'N'...'Z' => ch - 13,
            else => ch,
        };
    }
    return out;
}

pub fn main(init: std.process.Init) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("gate: usage: gate --staged | --tree | --commit-msg <file> | --log <range> | --diff <range> | --pr-body <file>\n", .{});
        return 2;
    }
    var names: std.ArrayList([]const u8) = .empty;
    for (encoded_names) |n| try names.append(arena, try rot13(arena, n));
    var g = Gate{ .arena = arena, .io = io, .names = names.items };
    const mode = args[1];
    if (std.mem.eql(u8, mode, "--staged")) {
        for (try g.stagedPaths()) |p| try g.checkFile(p);
    } else if (std.mem.eql(u8, mode, "--tree")) {
        for (try g.trackedPaths()) |p| try g.checkFile(p);
    } else if (std.mem.eql(u8, mode, "--commit-msg") and args.len > 2) {
        const text = try Io.Dir.cwd().readFileAlloc(io, args[2], arena, .limited(max_file_scan_bytes));
        try g.checkMessage("the commit message", text);
    } else if (std.mem.eql(u8, mode, "--log") and args.len > 2) {
        try g.checkLogRange(args[2]);
    } else if (std.mem.eql(u8, mode, "--diff") and args.len > 2) {
        try g.checkDiffRange(args[2]);
    } else if (std.mem.eql(u8, mode, "--pr-body") and args.len > 2) {
        const text = try Io.Dir.cwd().readFileAlloc(io, args[2], arena, .limited(max_file_scan_bytes));
        try g.checkPrBody(text);
    } else {
        std.debug.print("gate: unknown mode {s}\n", .{mode});
        return 2;
    }
    var buffer: [4096]u8 = undefined;
    var writer = Io.File.stderr().writer(io, &buffer);
    const out = &writer.interface;
    for (g.hits.items) |hit| try out.print("{s}\n", .{hit});
    if (g.hits.items.len == 0) try out.print("gate: clean\n", .{}) else try out.print("gate: {d} hit(s)\n", .{g.hits.items.len});
    try out.flush();
    return if (g.hits.items.len == 0) 0 else 1;
}

test "rot13 round trips" {
    const a = std.testing.allocator;
    const once = try rot13(a, "Gossveil");
    defer a.free(once);
    const twice = try rot13(a, once);
    defer a.free(twice);
    try std.testing.expectEqualStrings("Gossveil", twice);
}
