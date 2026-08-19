cat > input/script.lua <<'EOF'
local message = "hi boi"

local function greet(name)
    print(message, name)
end

local players = game:GetService("Players")

if players then
    greet("Roblox")
end

for i = 1, 3 do
    print(i)
end
EOF