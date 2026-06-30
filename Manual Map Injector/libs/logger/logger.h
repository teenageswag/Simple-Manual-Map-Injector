#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <memory>
#include <mutex>
#include <source_location>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#undef ERROR
#endif

namespace log_detail {

    enum class Level : uint8_t { TRACE, DEBUG, INFO, WARN, ERROR };

    struct LogMessage {
        Level level;
        std::chrono::system_clock::time_point time;
        uint32_t thread_id;
        std::source_location loc;
        std::string text;
    };

    class Sink {
    public:
        virtual ~Sink() = default;
        virtual void write(const LogMessage& msg) = 0;
        virtual void flush() = 0;
    };

    inline std::string_view level_to_string(Level level) noexcept {
        switch (level) {
        case Level::TRACE: return "TRC";
        case Level::DEBUG: return "DBG";
        case Level::INFO:  return "INF";
        case Level::WARN:  return "WRN";
        case Level::ERROR: return "ERR";
        default:           return "UNK";
        }
    }

    inline std::string_view level_to_color(Level level) noexcept {
        switch (level) {
        case Level::TRACE: return "\x1b[38;2;140;140;140m"; // #8C8C8C
        case Level::DEBUG: return "\x1b[38;2;128;191;64m";  // #80BF40
        case Level::INFO:  return "\x1b[38;2;51;166;204m";  // #33A6CC
        case Level::WARN:  return "\x1b[38;2;204;191;51m";  // #CCBF33
        case Level::ERROR: return "\x1b[38;2;204;51;64m";   // #CC3340
        default:           return "\x1b[0m";                // Reset
        }
    }

    inline constexpr std::string_view reset_color = "\x1b[0m";

    inline void get_time_info(std::chrono::system_clock::time_point tp, struct tm& tm_info) {
        auto t_c = std::chrono::system_clock::to_time_t(tp);
#if defined(_WIN32)
        localtime_s(&tm_info, &t_c);
#else
        localtime_r(&t_c, &tm_info);
#endif
    }

    struct ConsoleSinkConfig {
        bool auto_alloc = true;
        std::string title = "";
        uint16_t buffer_width = 120;
        uint16_t buffer_height = 30;
        bool redirect_streams = true;
    };

    class ConsoleSink : public Sink {
    public:
        ConsoleSink(ConsoleSinkConfig cfg = {}) {
#if defined(_WIN32)
            if (cfg.auto_alloc && GetConsoleWindow() == NULL) {
                AllocConsole();
            }

            if (!cfg.title.empty()) {
                SetConsoleTitleA(cfg.title.c_str());
            }

            if (cfg.redirect_streams) {
                FILE* fDummy;
                freopen_s(&fDummy, "CONOUT$", "w", stdout);
                freopen_s(&fDummy, "CONOUT$", "w", stderr);
                freopen_s(&fDummy, "CONIN$", "r", stdin);
            }

            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            if (hOut != INVALID_HANDLE_VALUE) {
                COORD coord = { static_cast<SHORT>(cfg.buffer_width), static_cast<SHORT>(cfg.buffer_height) };
                SetConsoleScreenBufferSize(hOut, coord);

                DWORD dwMode = 0;
                if (GetConsoleMode(hOut, &dwMode)) {
                    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                }
            }

            HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
            if (hErr != INVALID_HANDLE_VALUE) {
                DWORD dwMode = 0;
                if (GetConsoleMode(hErr, &dwMode)) {
                    SetConsoleMode(hErr, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                }
            }

            SetConsoleOutputCP(CP_UTF8);
            SetConsoleCP(CP_UTF8);
#endif
        }

        void write(const LogMessage& msg) override {
            struct tm tm_info;
            get_time_info(msg.time, tm_info);

            std::string_view filename = msg.loc.file_name();
            if (auto pos = filename.find_last_of("/\\"); pos != std::string_view::npos) {
                filename = filename.substr(pos + 1);
            }

            std::string final_msg = std::format(
                "{}[{:02}:{:02}:{:02}] [{}] [{}:{}] {}{}\n",
                level_to_color(msg.level),
                tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec,
                level_to_string(msg.level),
                filename, msg.loc.line(),
                msg.text,
                reset_color
            );

            if (msg.level >= Level::ERROR) {
                std::fputs(final_msg.c_str(), stderr);
            }
            else {
                std::fputs(final_msg.c_str(), stdout);
            }
        }

        void flush() override {
            std::fflush(stdout);
            std::fflush(stderr);
        }
    };

    class FileSink : public Sink {
        std::filesystem::path path_;
        std::ofstream file_;
        size_t max_size_;
        size_t current_size_ = 0;

        void open_file() {
            file_.open(path_, std::ios::app);
            if (file_.is_open()) {
                file_.seekp(0, std::ios::end);
                current_size_ = static_cast<size_t>(file_.tellp());
            }
        }

        void rotate() {
            if (file_.is_open()) file_.close();

            auto rotated_path = path_;
            rotated_path += ".1";

            std::error_code ec;
            if (std::filesystem::exists(path_, ec)) {
                if (std::filesystem::exists(rotated_path, ec)) {
                    std::filesystem::remove(rotated_path, ec);
                }
                std::filesystem::rename(path_, rotated_path, ec);
            }
            open_file();
        }

    public:
        explicit FileSink(std::filesystem::path path, size_t max_size = 5 * 1024 * 1024)
            : path_(std::move(path)), max_size_(max_size) {
            open_file();
        }

        void write(const LogMessage& msg) override {
            if (!file_.is_open()) return;

            struct tm tm_info;
            get_time_info(msg.time, tm_info);

            std::string_view filename = msg.loc.file_name();
            if (auto pos = filename.find_last_of("/\\"); pos != std::string_view::npos) {
                filename = filename.substr(pos + 1);
            }

            std::string formatted = std::format(
                "[{:04}-{:02}-{:02} {:02}:{:02}:{:02}] [{}] [{}:{}] {}\n",
                tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
                tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec,
                level_to_string(msg.level),
                filename, msg.loc.line(),
                msg.text
            );

            if (current_size_ + formatted.size() > max_size_) {
                rotate();
                if (!file_.is_open()) return;
            }

            file_.write(formatted.data(), formatted.size());
            current_size_ += formatted.size();
        }

        void flush() override {
            if (file_.is_open()) file_.flush();
        }
    };

    class Logger {
        std::vector<std::unique_ptr<Sink>> sinks_;
        Level min_level_ = Level::INFO;
        std::mutex sinks_mutex_;

        static constexpr size_t queue_capacity = 4096;
        std::vector<LogMessage> queue_;
        size_t head_ = 0;
        size_t tail_ = 0;
        size_t count_ = 0;

        std::mutex queue_mutex_;
        std::condition_variable cv_push_;
        std::condition_variable cv_pop_;
        std::thread worker_;
        bool stop_ = false;

        Logger() : queue_(queue_capacity) {
#if defined(_WIN32)
            if (GetConsoleWindow() != NULL) {
                ConsoleSinkConfig cfg;
                cfg.auto_alloc = false;
                sinks_.push_back(std::make_unique<ConsoleSink>(cfg));
            }
#else
            sinks_.push_back(std::make_unique<ConsoleSink>());
#endif
            worker_ = std::thread(&Logger::worker_loop, this);
        }

        ~Logger() {
            {
                std::unique_lock lock(queue_mutex_);
                stop_ = true;
            }
            cv_pop_.notify_one();
            if (worker_.joinable()) worker_.join();

            flush_sinks();
        }

        void worker_loop() {
            std::vector<LogMessage> local_batch;
            local_batch.reserve(256);

            while (true) {
                {
                    std::unique_lock lock(queue_mutex_);
                    cv_pop_.wait_for(lock, std::chrono::milliseconds(500), [this] {
                        return count_ > 0 || stop_;
                        });

                    if (stop_ && count_ == 0) break;

                    while (count_ > 0 && local_batch.size() < 256) {
                        local_batch.push_back(std::move(queue_[head_]));
                        head_ = (head_ + 1) % queue_capacity;
                        --count_;
                    }
                }

                if (!local_batch.empty()) {
                    cv_push_.notify_all();

                    std::lock_guard lock(sinks_mutex_);
                    bool should_flush = false;
                    for (const auto& msg : local_batch) {
                        for (auto& sink : sinks_) {
                            sink->write(msg);
                        }
                        if (msg.level >= Level::ERROR) should_flush = true;
                    }
                    if (should_flush) flush_sinks_unsafe();

                    local_batch.clear();
                }
                else {
                    flush_sinks();
                }
            }
        }

        void flush_sinks_unsafe() {
            for (auto& sink : sinks_) sink->flush();
        }

        void flush_sinks() {
            std::lock_guard lock(sinks_mutex_);
            flush_sinks_unsafe();
        }

        static uint32_t get_current_thread_id() {
            thread_local uint32_t tid = []() {
#if defined(_WIN32)
                return static_cast<uint32_t>(GetCurrentThreadId());
#else
                return static_cast<uint32_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
#endif
                }();
            return tid;
        }

    public:
        static Logger& instance() {
            static Logger inst;
            return inst;
        }

        Logger(const Logger&) = delete;
        Logger& operator=(const Logger&) = delete;

        void set_level(Level level) {
            min_level_ = level;
        }

        Level get_level() const {
            return min_level_;
        }

        void add_sink(std::unique_ptr<Sink> sink) {
            std::lock_guard lock(sinks_mutex_);
            sinks_.push_back(std::move(sink));
        }

        void remove_console_sinks() {
            std::lock_guard lock(sinks_mutex_);
            for (auto it = sinks_.begin(); it != sinks_.end(); ) {
                if (dynamic_cast<ConsoleSink*>(it->get())) {
                    it = sinks_.erase(it);
                }
                else {
                    ++it;
                }
            }
        }

        void enqueue(Level level, const std::source_location& loc, std::string_view text) {
            if (level < min_level_) return;

            std::unique_lock lock(queue_mutex_);
            cv_push_.wait(lock, [this] { return count_ < queue_capacity; });

            auto& entry = queue_[tail_];
            entry.level = level;
            entry.time = std::chrono::system_clock::now();
            entry.thread_id = get_current_thread_id();
            entry.loc = loc;

            entry.text.assign(text);

            tail_ = (tail_ + 1) % queue_capacity;
            ++count_;

            lock.unlock();
            cv_pop_.notify_one();
        }
    };

    template <typename... Args>
    struct log_format_string {
        std::format_string<Args...> fmt;
        std::source_location loc;

        template <typename String>
        consteval log_format_string(const String& s, const std::source_location& l = std::source_location::current())
            : fmt(s), loc(l) {
        }
    };

    inline void log_impl(Level level, const std::source_location& loc, std::string_view text) {
        if (level < Logger::instance().get_level()) return;
        Logger::instance().enqueue(level, loc, text);
    }

} // namespace log_detail

// Default compile-time active level
#ifndef LOG_ACTIVE_LEVEL
#define LOG_ACTIVE_LEVEL log::Level::TRACE
#endif

// We use a struct to avoid namespace conflicts with std::log / ::log
struct log {
    using Level = log_detail::Level;
    using Sink = log_detail::Sink;
    using ConsoleConfig = log_detail::ConsoleSinkConfig;

    static void set_level(Level level) {
        log_detail::Logger::instance().set_level(level);
    }

    static void add_file_sink(const std::filesystem::path& path, size_t max_size = 5 * 1024 * 1024) {
        log_detail::Logger::instance().add_sink(std::make_unique<log_detail::FileSink>(path, max_size));
    }

    static void add_console_sink(ConsoleConfig cfg = {}) {
        log_detail::Logger::instance().remove_console_sinks();
        log_detail::Logger::instance().add_sink(std::make_unique<log_detail::ConsoleSink>(std::move(cfg)));
    }

    static void remove_console_sink() {
        log_detail::Logger::instance().remove_console_sinks();
    }

    static void init_console(ConsoleConfig cfg = {}) {
        add_console_sink(std::move(cfg));
    }

    template <typename... Args>
    static void trace(log_detail::log_format_string<std::type_identity_t<Args>...> fmt, Args&&... args) {
        if constexpr (LOG_ACTIVE_LEVEL <= Level::TRACE) {
            if (Level::TRACE < log_detail::Logger::instance().get_level()) return;
            thread_local std::string tls_buffer;
            tls_buffer.clear();
            std::format_to(std::back_inserter(tls_buffer), fmt.fmt, std::forward<Args>(args)...);
            log_detail::log_impl(Level::TRACE, fmt.loc, tls_buffer);
        }
    }

    template <typename... Args>
    static void debug(log_detail::log_format_string<std::type_identity_t<Args>...> fmt, Args&&... args) {
        if constexpr (LOG_ACTIVE_LEVEL <= Level::DEBUG) {
            if (Level::DEBUG < log_detail::Logger::instance().get_level()) return;
            thread_local std::string tls_buffer;
            tls_buffer.clear();
            std::format_to(std::back_inserter(tls_buffer), fmt.fmt, std::forward<Args>(args)...);
            log_detail::log_impl(Level::DEBUG, fmt.loc, tls_buffer);
        }
    }

    template <typename... Args>
    static void info(log_detail::log_format_string<std::type_identity_t<Args>...> fmt, Args&&... args) {
        if constexpr (LOG_ACTIVE_LEVEL <= Level::INFO) {
            if (Level::INFO < log_detail::Logger::instance().get_level()) return;
            thread_local std::string tls_buffer;
            tls_buffer.clear();
            std::format_to(std::back_inserter(tls_buffer), fmt.fmt, std::forward<Args>(args)...);
            log_detail::log_impl(Level::INFO, fmt.loc, tls_buffer);
        }
    }

    template <typename... Args>
    static void warn(log_detail::log_format_string<std::type_identity_t<Args>...> fmt, Args&&... args) {
        if constexpr (LOG_ACTIVE_LEVEL <= Level::WARN) {
            if (Level::WARN < log_detail::Logger::instance().get_level()) return;
            thread_local std::string tls_buffer;
            tls_buffer.clear();
            std::format_to(std::back_inserter(tls_buffer), fmt.fmt, std::forward<Args>(args)...);
            log_detail::log_impl(Level::WARN, fmt.loc, tls_buffer);
        }
    }

    template <typename... Args>
    static void error(log_detail::log_format_string<std::type_identity_t<Args>...> fmt, Args&&... args) {
        if constexpr (LOG_ACTIVE_LEVEL <= Level::ERROR) {
            if (Level::ERROR < log_detail::Logger::instance().get_level()) return;
            thread_local std::string tls_buffer;
            tls_buffer.clear();
            std::format_to(std::back_inserter(tls_buffer), fmt.fmt, std::forward<Args>(args)...);
            log_detail::log_impl(Level::ERROR, fmt.loc, tls_buffer);
        }
    }
};
