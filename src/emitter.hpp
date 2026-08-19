cat > src/emitter.hpp <<'EOF'
#pragma once

#include <string>

class Emitter
{
public:
    std::string emit(const std::string& source);
};
EOF