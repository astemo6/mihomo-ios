#ifndef NC_LUA_BRIDGE_H
#define NC_LUA_BRIDGE_H

#include <stddef.h>
#include <stdint.h>
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t current_bytes;
    size_t peak_bytes;
    size_t max_bytes; /* Hard limit e.g. 2 * 1024 * 1024 (2 MB); 0 = unlimited */
} NCLuaMemTracker;

void* nc_lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize);
lua_State* nc_lua_newstate(NCLuaMemTracker *tracker, size_t max_bytes);
void nc_lua_close(lua_State *L);

/* Execution deadline: a LUA_MASKCOUNT hook checks the wall clock every
** NCLUA_HOOK_INTERVAL instructions and raises a Lua error once the deadline
** has passed (the same "runaway script only kills its own run" contract the
** JSC engine gets from JSContextGroupSetExecutionTimeLimit). seconds <= 0
** clears the deadline. */
#define NCLUA_HOOK_INTERVAL 65536
void nc_lua_set_deadline(lua_State *L, double seconds);
double nc_lua_deadline_left(lua_State *L);
int nc_lua_load_string(lua_State *L, const char *code, size_t len, const char *chunkname);
int nc_lua_pcall(lua_State *L, int nargs, int nresults);
const char* nc_lua_get_error(lua_State *L);

void nc_lua_set_context_ptr(lua_State *L, void *ptr);
void* nc_lua_get_context_ptr(lua_State *L);

void nc_lua_register_fn(lua_State *L, const char *table_name, const char *fn_name, lua_CFunction fn);
void nc_lua_push_bytes(lua_State *L, const char *bytes, size_t len);
const char* nc_lua_get_bytes(lua_State *L, int idx, size_t *out_len);

/* S2 helpers: the pieces of the Lua C API that are macros in lua.h (and so
** invisible to Swift) wrapped as real functions. */
/* Push a C closure carrying one light-userdata upvalue (host-object handle). */
void nc_lua_push_closure(lua_State *L, lua_CFunction fn, void *upvalue);
/* Inside such a closure: the upvalue pointer (lua_upvalueindex(1)). */
void* nc_lua_upvalue_ptr(lua_State *L);
/* Create the per-connection ctx table and keep it in the registry; the
** Shadowrocket-style callbacks receive this same table as their first
** argument on every call. */
void nc_lua_init_context(lua_State *L);
void nc_lua_push_context(lua_State *L);

/* Host-module plumbing (kept in C so Swift never touches macro-only API):
** ensure global table t1 (and nested table t1.t2 when t2 != NULL) exists,
** set fields on it, and register C functions into it. */
void nc_lua_register_nested(lua_State *L, const char *t1, const char *t2, const char *fn_name, lua_CFunction fn);
void nc_lua_set_table_int(lua_State *L, const char *t1, const char *t2, const char *field, long long v);
void nc_lua_set_table_string(lua_State *L, const char *t1, const char *t2, const char *field, const char *v);
void nc_lua_set_table_bool(lua_State *L, const char *t1, const char *t2, const char *field, int v);

#ifdef __cplusplus
}
#endif

#endif /* NC_LUA_BRIDGE_H */
