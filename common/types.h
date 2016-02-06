///
/// types.h
///
/// Created on: Feb 6, 2016
///     Author: alexen
///

#pragma once

#include <vector>
#include <memory>

namespace common {


using Buffer = std::vector< char >;

template< typename T, typename RetT, typename ArgT >
using deleter_of = RetT(*)( ArgT );

template< typename T, typename DeleterRetT = void, typename DeleterArgT = T* >
using autoclean_unique_ptr = std::unique_ptr< T, deleter_of< T, DeleterRetT, DeleterArgT > >;


} // namespace common
