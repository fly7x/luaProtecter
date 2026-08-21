#include "bytecode.hpp"

// Bytecode currently stores raw Luau bytecode.
//
// Keeping this implementation file allows us to add
// validation, serialization, or package metadata later
// without changing the public interface.