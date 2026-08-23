/** template.h — template 攻击接口。 */
#pragma once

#include <string>

#include "../target.h"

namespace zemu::attack {

int runTemplate(const target::Target& tgt, const std::string& corpusPath,
                const std::string& modelFilter, const std::string& behavior,
                bool verbose);

}  // namespace zemu::attack
