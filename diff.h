// diff.h - compares two JSON reports (W35): which activities got worse between a run before a
// change and a run after it, for use as a CI gate. A small JSON reader is included, so there is
// no third-party library (D3). It makes no Windows calls (D7).

#ifndef WAITWHY_DIFF_H
#define WAITWHY_DIFF_H

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace waitwhy {

// ---------------------------------------------------------------------------
// A JSON value and a reader for it
// ---------------------------------------------------------------------------

struct JsonValue {
  enum class Type { Null, Bool, Number, String, Array, Object };
  Type type = Type::Null;
  bool boolean = false;
  double number = 0;
  std::string text;
  std::vector<JsonValue> items;                               // Array
  std::vector<std::pair<std::string, JsonValue>> members;     // Object, in order

  const JsonValue* Get(const std::string& key) const {
    for (const auto& [k, v] : members)
      if (k == key) return &v;
    return nullptr;
  }
  std::string Str(const std::string& key) const {
    const JsonValue* v = Get(key);
    return v && v->type == Type::String ? v->text : std::string();
  }
  double Num(const std::string& key) const {
    const JsonValue* v = Get(key);
    return v && v->type == Type::Number ? v->number : 0.0;
  }
};

class JsonReader {
 public:
  explicit JsonReader(const std::string& text) : s_(text) {}

  // Reads one value covering the whole text; false with an error message otherwise.
  bool Read(JsonValue* out, std::string* error) {
    if (!Value(out) || (Space(), pos_ != s_.size())) {
      if (error) *error = "not valid JSON near character " + std::to_string(pos_);
      return false;
    }
    return true;
  }

 private:
  void Space() {
    while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\n' || s_[pos_] == '\r')) ++pos_;
  }
  bool Literal(const char* word) {
    const size_t n = std::char_traits<char>::length(word);
    if (s_.compare(pos_, n, word) != 0) return false;
    pos_ += n;
    return true;
  }
  bool Value(JsonValue* v) {
    Space();
    if (pos_ >= s_.size()) return false;
    const char c = s_[pos_];
    if (c == '{') return Object(v);
    if (c == '[') return Array(v);
    if (c == '"') {
      v->type = JsonValue::Type::String;
      return String(&v->text);
    }
    if (Literal("true")) return v->type = JsonValue::Type::Bool, v->boolean = true, true;
    if (Literal("false")) return v->type = JsonValue::Type::Bool, v->boolean = false, true;
    if (Literal("null")) return v->type = JsonValue::Type::Null, true;
    const char* start = s_.c_str() + pos_;
    char* end = nullptr;
    v->number = std::strtod(start, &end);
    if (end == start) return false;
    v->type = JsonValue::Type::Number;
    pos_ += static_cast<size_t>(end - start);
    return true;
  }
  bool String(std::string* out) {
    ++pos_;  // the opening quote
    while (pos_ < s_.size()) {
      const char c = s_[pos_++];
      if (c == '"') return true;
      if (c != '\\') {
        *out += c;
        continue;
      }
      if (pos_ >= s_.size()) return false;
      const char e = s_[pos_++];
      switch (e) {
        case 'n': *out += '\n'; break;
        case 't': *out += '\t'; break;
        case 'r': *out += '\r'; break;
        case 'b': *out += '\b'; break;
        case 'f': *out += '\f'; break;
        case 'u': {
          if (pos_ + 4 > s_.size()) return false;
          const unsigned code = static_cast<unsigned>(std::strtoul(s_.substr(pos_, 4).c_str(), nullptr, 16));
          pos_ += 4;
          // UTF-8 for the Basic Multilingual Plane; waitwhy writes \u only for control characters.
          if (code < 0x80) {
            *out += static_cast<char>(code);
          } else if (code < 0x800) {
            *out += static_cast<char>(0xC0 | (code >> 6));
            *out += static_cast<char>(0x80 | (code & 0x3F));
          } else {
            *out += static_cast<char>(0xE0 | (code >> 12));
            *out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
            *out += static_cast<char>(0x80 | (code & 0x3F));
          }
          break;
        }
        default: *out += e;  // \" \\ \/
      }
    }
    return false;
  }
  bool Array(JsonValue* v) {
    v->type = JsonValue::Type::Array;
    ++pos_;
    Space();
    if (pos_ < s_.size() && s_[pos_] == ']') return ++pos_, true;
    for (;;) {
      JsonValue item;
      if (!Value(&item)) return false;
      v->items.push_back(std::move(item));
      Space();
      if (pos_ >= s_.size()) return false;
      if (s_[pos_] == ']') return ++pos_, true;
      if (s_[pos_++] != ',') return false;
    }
  }
  bool Object(JsonValue* v) {
    v->type = JsonValue::Type::Object;
    ++pos_;
    Space();
    if (pos_ < s_.size() && s_[pos_] == '}') return ++pos_, true;
    for (;;) {
      Space();
      std::string key;
      if (pos_ >= s_.size() || s_[pos_] != '"' || !String(&key)) return false;
      Space();
      if (pos_ >= s_.size() || s_[pos_++] != ':') return false;
      JsonValue member;
      if (!Value(&member)) return false;
      v->members.emplace_back(std::move(key), std::move(member));
      Space();
      if (pos_ >= s_.size()) return false;
      if (s_[pos_] == '}') return ++pos_, true;
      if (s_[pos_++] != ',') return false;
    }
  }

  const std::string& s_;
  size_t pos_ = 0;
};

// ---------------------------------------------------------------------------
// Comparing two reports
// ---------------------------------------------------------------------------

// The name a thread gave itself, from a label such as "Thread 4632 (main)" or
// "Thread 964 (main, exited) [PID 7]": thread IDs differ between runs, names do not.
inline std::string ThreadNameOf(const std::string& label) {
  const size_t open = label.find('(');
  if (open == std::string::npos) return "(unnamed)";
  const size_t close = label.find_first_of(",)", open);
  std::string name = label.substr(open + 1, close == std::string::npos ? std::string::npos : close - open - 1);
  return name == "exited" || name.empty() ? "(unnamed)" : name;
}

struct DiffRow {
  std::string thread, category, yourCode;
  double before = 0, after = 0;  // share of the thread's time, percent; 0 when not reported
  bool findingBefore = false, findingAfter = false;
  double Change() const { return after - before; }
};

struct ReportDiff {
  std::vector<DiffRow> rows;  // sleeps left out, most worsened first
  bool worse = false;         // over the threshold
  std::string beforeProgram, afterProgram;
};

// Activities are matched by thread name, category and function in the program's code. With a
// threshold, the result is worse when an activity's share grew by more than that many points,
// or a finding appeared that was not there before.
inline ReportDiff DiffReports(const JsonValue& before, const JsonValue& after, double thresholdPoints) {
  ReportDiff d;
  d.beforeProgram = before.Str("program");
  d.afterProgram = after.Str("program");
  std::map<std::tuple<std::string, std::string, std::string>, DiffRow> rows;
  auto add = [&rows](const JsonValue& report, bool isAfter) {
    if (const JsonValue* waits = report.Get("waits"))
      for (const JsonValue& w : waits->items) {
        const std::string category = w.Str("category");
        if (category == "sleep") continue;
        DiffRow& r = rows[{ThreadNameOf(w.Str("thread")), category, w.Str("yourCode")}];
        r.thread = ThreadNameOf(w.Str("thread"));
        r.category = category;
        r.yourCode = w.Str("yourCode");
        (isAfter ? r.after : r.before) += w.Num("pct");
      }
    if (const JsonValue* findings = report.Get("findings"))
      for (const JsonValue& f : findings->items) {
        if (f.Str("kind") != "wait") continue;
        DiffRow& r = rows[{ThreadNameOf(f.Str("thread")), f.Str("category"), f.Str("yourCode")}];
        r.thread = ThreadNameOf(f.Str("thread"));
        r.category = f.Str("category");
        r.yourCode = f.Str("yourCode");
        (isAfter ? r.findingAfter : r.findingBefore) = true;
      }
  };
  add(before, false);
  add(after, true);
  for (auto& [key, r] : rows) {
    d.rows.push_back(r);
    if (thresholdPoints >= 0 && (r.Change() > thresholdPoints || (r.findingAfter && !r.findingBefore)))
      d.worse = true;
  }
  std::stable_sort(d.rows.begin(), d.rows.end(),
                   [](const DiffRow& x, const DiffRow& y) { return x.Change() > y.Change(); });
  return d;
}

inline std::string RenderDiff(const ReportDiff& d, double thresholdPoints) {
  std::string out;
  char line[512];
  std::snprintf(line, sizeof line, "waitwhy diff: %s (before) -> %s (after)\n\n",
                d.beforeProgram.c_str(), d.afterProgram.c_str());
  out += line;
  std::snprintf(line, sizeof line, "  %8s %8s %8s  %s\n", "Before", "After", "Change", "Thread, waiting on, in");
  out += line;
  for (const DiffRow& r : d.rows) {
    std::snprintf(line, sizeof line, "  %7.0f%% %7.0f%% %+7.0f   %s, %s, in %s%s\n", r.before, r.after,
                  r.Change(), r.thread.c_str(), r.category.c_str(), r.yourCode.c_str(),
                  r.findingAfter && !r.findingBefore ? "  (new finding)"
                  : r.findingBefore && !r.findingAfter ? "  (finding gone)" : "");
    out += line;
  }
  if (d.rows.empty()) out += "  (no waits apart from sleeps in either report)\n";
  if (thresholdPoints >= 0) {
    std::snprintf(line, sizeof line, "\n%s\n",
                  d.worse ? "Worse: an activity grew by more than the allowed points, or a finding is new."
                          : "Not worse than allowed.");
    out += line;
  }
  return out;
}

}  // namespace waitwhy

#endif  // WAITWHY_DIFF_H
