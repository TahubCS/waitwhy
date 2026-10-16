// html.h - the report as one self-contained HTML page (W36): the findings in the text report's
// words, each measured wait chain as a bar, a per-thread timeline, the biggest waits with
// their call stacks, an off-CPU flame graph and the data-quality section. Everything is inline
// (CSS and SVG, no script, no network), so the file can be mailed or attached to a bug. No
// Windows calls (D7).

#ifndef WAITWHY_HTML_H
#define WAITWHY_HTML_H

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "analysis.h"
#include "export.h"
#include "report.h"

namespace waitwhy {

inline std::string HtmlEscape(const std::string& text) {
  std::string out;
  out.reserve(text.size());
  for (char c : text) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default: out += c;
    }
  }
  return out;
}

inline const char* CategoryColor(Category c) {
  switch (c) {
    case Category::Lock: return "#d62728";
    case Category::Disk: return "#1f77b4";
    case Category::Network: return "#9467bd";
    case Category::Sleep: return "#b8b8b8";
    case Category::OtherThread: return "#ff7f0e";
    case Category::PageFault: return "#8c564b";
    case Category::Other: break;
  }
  return "#7f7f7f";
}
constexpr char kRunningColor[] = "#2ca02c";
constexpr char kReadyColor[] = "#e6c229";
constexpr char kNotSeenColor[] = "#999999";

// At most `n` characters, with an ellipsis when cut (bytes; names are mostly ASCII).
inline std::string Shorten(const std::string& text, size_t n) {
  if (text.size() <= n) return text;
  return n > 3 ? text.substr(0, n - 3) + "..." : text.substr(0, n);
}

// Width of the bars of the timeline and the flame graph, in SVG units.
constexpr int kHtmlBars = 1000;

// One row per thread of the report: the window cut into kHtmlBars columns, each drawn in the
// state that had the most time in it, so the page stays small however long the trace was.
inline std::string HtmlTimeline(const Report& r, const Analyzer& an, const SymbolsFor& symbolsFor,
                                double ticksPerSecond) {
  if (an.lastTs <= an.firstTs || r.threads.empty()) return "<p>No timeline: nothing was seen in the window.</p>\n";
  const int label = 230, rowH = 18, top = 22;
  const double span = static_cast<double>(an.lastTs - an.firstTs);
  const int height = top + static_cast<int>(r.threads.size()) * rowH + 4;
  std::string out;
  Appendf(out, "<svg class=\"chart\" viewBox=\"0 0 %d %d\" role=\"img\" aria-label=\"Timeline of each thread\">\n",
          label + kHtmlBars, height);
  for (int k = 0; k <= 4; ++k) {
    const int x = label + kHtmlBars * k / 4;
    Appendf(out, "<line class=\"grid\" x1=\"%d\" y1=\"14\" x2=\"%d\" y2=\"%d\"/>", x, x, height);
    Appendf(out, "<text class=\"axis\" x=\"%d\" y=\"11\" text-anchor=\"%s\">%s</text>\n", x,
            k == 0 ? "start" : k == 4 ? "end" : "middle",
            HtmlEscape(FormatDuration(span / ticksPerSecond * k / 4)).c_str());
  }
  for (size_t row = 0; row < r.threads.size(); ++row) {
    const ThreadRow& t = r.threads[row];
    SymbolSource& sym = symbolsFor(an.ProcessOf(t.tid));
    const int y = top + static_cast<int>(row) * rowH;
    Appendf(out, "<text class=\"label\" x=\"%d\" y=\"%d\" text-anchor=\"end\"><title>%s</title>%s</text>\n",
            label - 6, y + 12, HtmlEscape(t.label).c_str(), HtmlEscape(Shorten(t.label, 34)).c_str());
    std::vector<std::pair<std::string, std::string>> keys;  // name, colour
    std::map<std::pair<std::string, std::string>, size_t> keyOf;
    std::vector<std::map<size_t, double>> columns(kHtmlBars);  // key -> ticks in the column
    for (const TimelineSlice& s : ThreadTimeline(an, t.tid)) {
      const double a = static_cast<double>((std::max)(s.start, an.firstTs) - an.firstTs);
      const double b = static_cast<double>((std::min)(s.end, an.lastTs) - an.firstTs);
      if (b <= a) continue;
      const std::string color = s.kind == Interval::Running ? kRunningColor
                                : s.kind == Interval::Ready ? kReadyColor
                                : s.bucket                  ? CategoryColor(CategoryOfBucket(an, *s.bucket, sym))
                                                            : kNotSeenColor;
      const std::pair<std::string, std::string> key{SliceName(an, s, sym), color};
      auto found = keyOf.find(key);
      if (found == keyOf.end()) {
        found = keyOf.emplace(key, keys.size()).first;
        keys.push_back(key);
      }
      const double perColumn = span / kHtmlBars;
      const int c0 = (std::min)(kHtmlBars - 1, static_cast<int>(a / perColumn));
      const int c1 = (std::min)(kHtmlBars - 1, static_cast<int>(b / perColumn));
      for (int c = c0; c <= c1; ++c) {
        const double overlap = (std::min)(b, (c + 1) * perColumn) - (std::max)(a, c * perColumn);
        if (overlap > 0) columns[static_cast<size_t>(c)][found->second] += overlap;
      }
    }
    // Runs of columns with the same state become one rectangle.
    auto dominant = [&columns](int c) {
      size_t best = SIZE_MAX;
      double bestTicks = 0;
      for (const auto& [key, ticks] : columns[static_cast<size_t>(c)])
        if (ticks > bestTicks) best = key, bestTicks = ticks;
      return best;
    };
    for (int c = 0; c < kHtmlBars;) {
      const size_t key = dominant(c);
      int end = c + 1;
      while (end < kHtmlBars && dominant(end) == key) ++end;
      if (key != SIZE_MAX) {
        double ticks = 0;
        for (int k = c; k < end; ++k) {
          auto it = columns[static_cast<size_t>(k)].find(key);
          if (it != columns[static_cast<size_t>(k)].end()) ticks += it->second;
        }
        Appendf(out, "<rect x=\"%d\" y=\"%d\" width=\"%d\" height=\"%d\" fill=\"%s\"><title>%s: %s</title></rect>",
                label + c, y + 2, end - c, rowH - 4, keys[key].second.c_str(),
                HtmlEscape(keys[key].first).c_str(), HtmlEscape(FormatDuration(ticks / ticksPerSecond)).c_str());
      }
      c = end;
    }
    out += "\n";
  }
  out += "</svg>\n";
  return out;
}

// What the waker did while a thread waited (W25), as one bar of its parts.
inline std::string HtmlChainBar(const Finding& f) {
  std::string out = "<svg class=\"bar\" viewBox=\"0 0 1000 14\" preserveAspectRatio=\"none\" role=\"img\" aria-label=\"What the waker did\">";
  double x = 0;
  for (const ChainPart& p : f.chain) {
    const double w = p.pct * 10.0;
    const char* color = p.kind == ChainPart::Kind::Running ? kRunningColor
                        : p.kind == ChainPart::Kind::Ready ? kReadyColor
                        : p.kind == ChainPart::Kind::NotSeen ? kNotSeenColor
                                                             : CategoryColor(p.category);
    const std::string what = p.kind == ChainPart::Kind::Running   ? "running"
                             : p.kind == ChainPart::Kind::Ready   ? "waiting for a free CPU"
                             : p.kind == ChainPart::Kind::NotSeen ? "not seen"
                                                                  : std::string(CategorySentence(p.category)) + ", in " + p.yourCode;
    Appendf(out, "<rect x=\"%.1f\" y=\"0\" width=\"%.1f\" height=\"14\" fill=\"%s\"><title>%s: %s (%.0f%%)</title></rect>",
            x, w, color, HtmlEscape(what).c_str(), HtmlEscape(FormatDuration(p.seconds)).c_str(), p.pct);
    x += w;
  }
  out += "</svg>\n";
  return out;
}

// The call stacks of one row of "Biggest waits", most wait time first.
inline std::string HtmlStacks(const WaitRow& w, const Analyzer& an, SymbolSource& sym, double ticksPerSecond) {
  std::vector<const Bucket*> buckets;
  for (const auto& [key, b] : an.buckets)
    if (b.tid == w.tid && CategoryOfBucket(an, b, sym) == w.category && YourCodeFrame(b, sym) == w.yourCode)
      buckets.push_back(&b);
  std::stable_sort(buckets.begin(), buckets.end(),
                   [](const Bucket* x, const Bucket* y) { return x->ticks > y->ticks; });
  std::string out;
  const size_t shown = (std::min)(buckets.size(), size_t{3});
  Appendf(out, "<details><summary>Call stacks (%zu of %zu)</summary>\n", shown, buckets.size());
  for (size_t i = 0; i < shown; ++i) {
    const Bucket& b = *buckets[i];
    Appendf(out, "<p>%u wait(s), %s, innermost frame first:</p>\n<ol class=\"stack\">", b.count,
            HtmlEscape(FormatDuration(static_cast<double>(b.ticks) / ticksPerSecond)).c_str());
    if (b.stack.empty()) out += "<li>(no call stack was recorded)</li>";
    for (uint64_t a : b.stack) {
      const std::string name = sym.Name(a);
      if (sym.IsExeFrame(name))
        Appendf(out, "<li><b>%s</b></li>", HtmlEscape(name).c_str());
      else
        Appendf(out, "<li>%s</li>", HtmlEscape(name).c_str());
    }
    out += "</ol>\n";
  }
  out += "</details>";
  return out;
}

// Off-CPU flame graph, drawn top-down: all waits of the report's threads apart from intentional
// sleeps, by thread, then call stack from the outermost frame, then what the wait was on.
inline std::string HtmlFlameGraph(const Report& r, const Analyzer& an, const SymbolsFor& symbolsFor,
                                  double ticksPerSecond) {
  struct Node {
    std::string name;
    std::string color;
    double ticks = 0;
    std::map<std::string, size_t> children;
  };
  std::vector<Node> nodes(1);
  nodes[0].name = "all waits";
  nodes[0].color = "#c0c0c0";
  auto child = [&nodes](size_t parent, const std::string& name, const std::string& color) {
    auto it = nodes[parent].children.find(name);
    if (it != nodes[parent].children.end()) return it->second;
    Node n;
    n.name = name;
    n.color = color;
    nodes.push_back(n);
    return nodes[parent].children[name] = nodes.size() - 1;
  };
  std::map<uint32_t, std::string> shown;
  for (const ThreadRow& t : r.threads) shown[t.tid] = t.label;
  for (const auto& [key, b] : an.buckets) {
    auto thread = shown.find(b.tid);
    if (thread == shown.end() || b.ticks == 0) continue;
    SymbolSource& sym = symbolsFor(an.ProcessOf(b.tid));
    const Category c = CategoryOfBucket(an, b, sym);
    if (c == Category::Sleep) continue;
    const double ticks = static_cast<double>(b.ticks);
    std::vector<size_t> path{0, child(0, thread->second, "#d0d0d0")};
    for (auto a = b.stack.rbegin(); a != b.stack.rend(); ++a) {
      const std::string name = sym.Name(*a);
      path.push_back(child(path.back(), name, sym.IsExeFrame(name) ? "#f2a541" : "#a9c5e0"));
    }
    path.push_back(child(path.back(), std::string("[") + CategoryLabel(c) + "]", CategoryColor(c)));
    for (size_t n : path) nodes[n].ticks += ticks;
  }
  if (nodes[0].ticks <= 0) return "<p>No waits apart from intentional sleeps.</p>\n";
  const int rowH = 17;
  const size_t maxDepth = 64;
  const double total = nodes[0].ticks;
  std::string rects;
  size_t deepest = 0;
  // Depth-first, children in name order like other flame graphs.
  std::vector<std::tuple<size_t, double, size_t>> todo{{0, 0.0, 0}};  // node, x, depth
  while (!todo.empty()) {
    const auto [n, x, depth] = todo.back();
    todo.pop_back();
    const Node& node = nodes[n];
    const double w = node.ticks / total * kHtmlBars;
    if (w < 0.5 || depth >= maxDepth) continue;
    deepest = (std::max)(deepest, depth);
    const double y = static_cast<double>(depth * rowH);
    Appendf(rects, "<g><title>%s: %s (%.1f%%)</title><rect x=\"%.2f\" y=\"%.0f\" width=\"%.2f\" height=\"%d\" fill=\"%s\"/>",
            HtmlEscape(node.name).c_str(), HtmlEscape(FormatDuration(node.ticks / ticksPerSecond)).c_str(),
            node.ticks / total * 100.0, x, y, w, rowH - 1, node.color.c_str());
    if (w >= 30)
      Appendf(rects, "<text class=\"frame\" x=\"%.2f\" y=\"%.0f\">%s</text>", x + 3, y + 12,
              HtmlEscape(Shorten(node.name, static_cast<size_t>(w / 6.5))).c_str());
    rects += "</g>\n";
    double cx = x;
    std::vector<std::tuple<size_t, double, size_t>> next;
    for (const auto& [name, c] : node.children) {
      next.emplace_back(c, cx, depth + 1);
      cx += nodes[c].ticks / total * kHtmlBars;
    }
    todo.insert(todo.end(), next.rbegin(), next.rend());
  }
  std::string out;
  Appendf(out, "<svg class=\"chart\" viewBox=\"0 0 %d %zu\" role=\"img\" aria-label=\"Off-CPU flame graph\">\n",
          kHtmlBars, (deepest + 1) * rowH);
  out += rects + "</svg>\n";
  return out;
}

inline std::string RenderHtml(const Report& r, const Analyzer& an, const SymbolsFor& symbolsFor,
                              double ticksPerSecond, const char* version) {
  std::string out;
  out += "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
         "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
  Appendf(out, "<title>waitwhy: %s</title>\n", HtmlEscape(r.program).c_str());
  out += R"css(<style>
:root { --bg: #ffffff; --fg: #1d1d1f; --muted: #6e6e73; --line: #d8d8dc; --panel: #f5f5f7; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #161618; --fg: #ececee; --muted: #a1a1a6; --line: #3a3a3d; --panel: #222225; }
}
body { background: var(--bg); color: var(--fg); margin: 0 auto; max-width: 1240px; padding: 0 16px 48px;
       font: 15px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
h1 { font-size: 1.5em; margin: 24px 0 4px; } h2 { font-size: 1.15em; margin: 32px 0 8px; }
.meta, .note { color: var(--muted); } .warn { color: #c0392b; }
pre { background: var(--panel); padding: 10px 12px; border-radius: 6px; overflow-x: auto;
      font: 13px/1.4 ui-monospace, Consolas, monospace; white-space: pre-wrap; margin: 0 0 6px; }
.finding { margin-bottom: 14px; } .caption { margin: 6px 0 3px; font-size: 13px; }
svg.chart { width: 100%; height: auto; display: block; }
svg.bar { width: 100%; height: 14px; display: block; }
svg text { fill: var(--fg); font: 11px system-ui, sans-serif; } svg text.axis { fill: var(--muted); }
svg text.frame { fill: #1d1d1f; pointer-events: none; } line.grid { stroke: var(--line); }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid var(--line); }
td.n { text-align: right; white-space: nowrap; } code { font: 13px ui-monospace, Consolas, monospace; word-break: break-all; }
ol.stack { font: 12px/1.5 ui-monospace, Consolas, monospace; margin: 4px 0 10px; word-break: break-all; }
.legend span { display: inline-block; margin: 0 14px 4px 0; } .legend i { display: inline-block; width: 11px; height: 11px;
       margin-right: 5px; vertical-align: -1px; border-radius: 2px; }
.q-high { color: #2ca02c; } .q-medium { color: #b8860b; } .q-low { color: #c0392b; }
.wrap { overflow-x: auto; }
</style>
</head>
<body>
)css";
  if (r.otherProcesses)
    Appendf(out, "<h1>waitwhy report: %s (PID %u) and %zu more process(es)</h1>\n", HtmlEscape(r.program).c_str(),
            r.pid, r.otherProcesses);
  else
    Appendf(out, "<h1>waitwhy report: %s (PID %u)</h1>\n", HtmlEscape(r.program).c_str(), r.pid);
  Appendf(out, "<p class=\"meta\">Watched for %s &middot; data quality: <b class=\"q-%s\">%s</b> &middot; waitwhy %s</p>\n",
          HtmlEscape(FormatDuration(r.windowSeconds)).c_str(), LevelName(r.quality.confidence),
          LevelName(r.quality.confidence), HtmlEscape(version).c_str());
  for (const std::string& w : r.warnings) Appendf(out, "<p class=\"warn\">Warning: %s</p>\n", HtmlEscape(w).c_str());

  out += "<h2 id=\"findings\">What this means</h2>\n";
  for (const Finding& f : r.findings) {
    std::string text = RenderFindingText(f), lines;
    for (size_t at = 0; at < text.size();) {  // without the text report's two-space indent
      size_t end = text.find('\n', at);
      if (end == std::string::npos) end = text.size();
      std::string line = text.substr(at, end - at);
      lines += (line.compare(0, 2, "  ") == 0 ? line.substr(2) : line) + "\n";
      at = end + 1;
    }
    Appendf(out, "<div class=\"finding\"><pre>%s</pre>", HtmlEscape(lines).c_str());
    if (!f.chain.empty()) {
      Appendf(out, "<p class=\"note caption\">What %s did while %s waited:</p>", HtmlEscape(f.waker).c_str(),
              HtmlEscape(f.thread).c_str());
      out += HtmlChainBar(f);
    }
    out += "</div>\n";
  }
  if (r.findings.empty()) out += "<p>No thread lost a significant share of its time to blocking (sleeps excluded).</p>\n";

  out += "<h2 id=\"timeline\">Timeline</h2>\n<p class=\"legend\">";
  const std::pair<const char*, const char*> legend[] = {
      {kRunningColor, "running"}, {kReadyColor, "wanted a CPU"}, {CategoryColor(Category::Lock), "lock"},
      {CategoryColor(Category::Disk), "disk"}, {CategoryColor(Category::Network), "network"},
      {CategoryColor(Category::OtherThread), "another thread"}, {CategoryColor(Category::PageFault), "page fault"},
      {CategoryColor(Category::Sleep), "sleep"}, {CategoryColor(Category::Other), "other"}};
  for (const auto& [color, what] : legend) Appendf(out, "<span><i style=\"background:%s\"></i>%s</span>", color, what);
  out += "</p>\n" + HtmlTimeline(r, an, symbolsFor, ticksPerSecond);
  out += "<p class=\"note\">Hover over a bar for what the thread was doing. Each pixel shows what took most of its time.</p>\n";

  out += "<h2 id=\"waits\">Biggest waits</h2>\n";
  if (!r.anyWaits) out += "<p>No waits recorded. Is the program doing anything?</p>\n";
  if (!r.waits.empty()) {
    out += "<div class=\"wrap\"><table>\n<tr><th>#</th><th>Thread</th><th>Waited</th><th>Share</th><th>Waits</th>"
           "<th>Longest</th><th>Waiting on</th><th>Your code, blocked in, woken by</th></tr>\n";
    for (size_t i = 0; i < r.waits.size(); ++i) {
      const WaitRow& w = r.waits[i];
      std::string blocked;
      for (size_t k = 0; k < w.blockedIn.size() && k < 3; ++k)
        Appendf(blocked, "%s%s (%.0f%%)", k ? ", " : "", w.blockedIn[k].first.c_str(), w.blockedIn[k].second);
      Appendf(out,
              "<tr><td class=\"n\">%zu</td><td>%s</td><td class=\"n\">%s%s</td><td class=\"n\">%.0f%%</td>"
              "<td class=\"n\">%u</td><td class=\"n\">%s</td><td><i style=\"color:%s\">&#9632;</i> %s</td>"
              "<td><code>%s</code><br>in <code>%s</code><br>woken by %s",
              i + 1, HtmlEscape(w.thread).c_str(), HtmlEscape(FormatDuration(w.seconds)).c_str(),
              w.stillWaitingAtEnd ? "+" : "", w.pct, w.count, HtmlEscape(FormatDuration(w.longestSeconds)).c_str(),
              CategoryColor(w.category), HtmlEscape(CategoryLabel(w.category)).c_str(), HtmlEscape(w.yourCode).c_str(),
              HtmlEscape(blocked).c_str(), HtmlEscape(w.wokenBy).c_str());
      if (!w.objects.empty()) Appendf(out, "<br>on <code>%s</code>", HtmlEscape(w.objects[0].first).c_str());
      out += HtmlStacks(w, an, symbolsFor(an.ProcessOf(w.tid)), ticksPerSecond) + "</td></tr>\n";
    }
    out += "</table></div>\n<p class=\"note\">+ still waiting when the trace ended.</p>\n";
  }
  if (r.hiddenWaitRows)
    Appendf(out, "<p class=\"note\">%zu smaller group(s) of waits not shown, %s in total.</p>\n", r.hiddenWaitRows,
            HtmlEscape(FormatDuration(r.hiddenWaitSeconds)).c_str());

  out += "<h2 id=\"flame\">Where the threads waited</h2>\n"
         "<p class=\"note\">An off-CPU flame graph: the width of each frame is the time spent waiting under it "
         "(intentional sleeps left out). Your program's own functions are orange; the last frame of each column "
         "says what the wait was on. Hover over a frame for its time.</p>\n";
  out += HtmlFlameGraph(r, an, symbolsFor, ticksPerSecond);

  out += "<h2 id=\"quality\">Data quality</h2>\n";
  std::string quality = RenderQualityText(r);
  if (!quality.empty() && quality[0] == '\n') quality.erase(0, 1);
  Appendf(out, "<pre>%s</pre>\n", HtmlEscape(quality).c_str());
  Appendf(out, "<p class=\"note\">Made by waitwhy %s. This page is self-contained and loads nothing from the network.</p>\n",
          HtmlEscape(version).c_str());
  out += "</body>\n</html>\n";
  return out;
}

}  // namespace waitwhy

#endif  // WAITWHY_HTML_H
