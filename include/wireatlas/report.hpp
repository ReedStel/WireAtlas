#pragma once

#include <string>

#include "wireatlas/model.hpp"

namespace wireatlas {

std::string render_table(const Analysis& analysis);
std::string render_summary(const Analysis& analysis);
std::string render_json(const Analysis& analysis, bool include_packets);

}  // namespace wireatlas
