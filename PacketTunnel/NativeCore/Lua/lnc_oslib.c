#define loslib_c
#define LUA_LIB

#include "lprefix.h"
#include <time.h>
#include <locale.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static int os_clock (lua_State *L) {
  lua_pushnumber(L, ((lua_Number)clock())/(lua_Number)CLOCKS_PER_SEC);
  return 1;
}

static int os_difftime (lua_State *L) {
  time_t t1 = (time_t)luaL_checkinteger(L, 1);
  time_t t2 = (time_t)luaL_optinteger(L, 2, 0);
  lua_pushnumber(L, (lua_Number)difftime(t1, t2));
  return 1;
}

static int os_time (lua_State *L) {
  time_t t = time(NULL);
  if (t == (time_t)(-1))
    return luaL_error(L, "time result cannot be represented in this installation");
  lua_pushinteger(L, (lua_Integer)t);
  return 1;
}

static const luaL_Reg syslib[] = {
  {"clock",     os_clock},
  {"difftime",  os_difftime},
  {"time",      os_time},
  {NULL, NULL}
};

LUAMOD_API int luaopen_os (lua_State *L) {
  luaL_newlib(L, syslib);
  return 1;
}
