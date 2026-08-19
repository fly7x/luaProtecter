cat > src/transformer.hpp <<'EOF'
#pragma once

#include <string>

class Transformer
{
public:
    std::string transform(const std::string& source);
};
EOF