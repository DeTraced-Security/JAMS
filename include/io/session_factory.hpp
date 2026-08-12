#pragma once

#include <span>
#include <cstdint>

namespace SMTP {
    struct ISession {
        virtual void on_data(std::span<const uint8_t>) = 0;
        virtual bool wants_close() const = 0;
        virtual ~ISession() = default;
    };
};