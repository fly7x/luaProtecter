cat > src/obfuscation.hpp <<'EOF'
#pragma once

#include <string>

class Obfuscator
{
public:
    std::string obfuscate(const std::string& source);
};
EOF