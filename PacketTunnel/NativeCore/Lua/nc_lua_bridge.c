#include "nc_lua_bridge.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

void* nc_lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize) {
    NCLuaMemTracker *tracker = (NCLuaMemTracker*)ud;
    if (nsize == 0) {
        if (ptr != NULL) {
            if (tracker != NULL) {
                if (tracker->current_bytes >= osize) {
                    tracker->current_bytes -= osize;
                } else {
                    tracker->current_bytes = 0;
                }
            }
            free(ptr);
        }
        return NULL;
    }
    if (tracker != NULL && tracker->max_bytes > 0) {
        size_t next_bytes = tracker->current_bytes + nsize - (ptr ? osize : 0);
        if (next_bytes > tracker->max_bytes) {
            return NULL; /* Memory limit exceeded */
        }
    }
    void *new_ptr = realloc(ptr, nsize);
    if (new_ptr != NULL && tracker != NULL) {
        tracker->current_bytes = tracker->current_bytes + nsize - (ptr ? osize : 0);
        if (tracker->current_bytes > tracker->peak_bytes) {
            tracker->peak_bytes = tracker->current_bytes;
        }
    }
    return new_ptr;
}

/* Deadline hook: the registry carries a malloc'd double (the absolute
** monotonic deadline). Checked every NCLUA_HOOK_INTERVAL instructions; past
** the deadline it raises a Lua error, which unwinds to the enclosing pcall —
** the state stays usable (the caller closes it: the run is poisoned, the
** tunnel is not). */
static double nc_lua_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

#define NC_DEADLINE_KEY "_nc_deadline"

static void nc_lua_deadline_hook(lua_State *L, lua_Debug *ar) {
    (void)ar;
    lua_getfield(L, LUA_REGISTRYINDEX, NC_DEADLINE_KEY);
    const double *at = (const double*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (at != NULL && nc_lua_now() > *at) {
        luaL_error(L, "lua script deadline exceeded (possible infinite loop or hang)");
    }
}

void nc_lua_set_deadline(lua_State *L, double seconds) {
    if (L == NULL) return;
    if (seconds <= 0) {
        lua_getfield(L, LUA_REGISTRYINDEX, NC_DEADLINE_KEY);
        void *old = lua_touserdata(L, -1);
        lua_pop(L, 1);
        free(old);
        lua_pushnil(L);
        lua_setfield(L, LUA_REGISTRYINDEX, NC_DEADLINE_KEY);
        lua_sethook(L, NULL, 0, 0);
        return;
    }
    lua_getfield(L, LUA_REGISTRYINDEX, NC_DEADLINE_KEY);
    double *at = (double*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (at == NULL) {
        at = (double*)malloc(sizeof(double));
        if (at == NULL) return; /* allocator is out of budget: the next Lua allocation errors anyway */
        lua_pushlightuserdata(L, at);
        lua_setfield(L, LUA_REGISTRYINDEX, NC_DEADLINE_KEY);
    }
    *at = nc_lua_now() + seconds;
    lua_sethook(L, nc_lua_deadline_hook, LUA_MASKCOUNT, NCLUA_HOOK_INTERVAL);
}

double nc_lua_deadline_left(lua_State *L) {
    if (L == NULL) return 0;
    lua_getfield(L, LUA_REGISTRYINDEX, NC_DEADLINE_KEY);
    const double *at = (const double*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (at == NULL) return 0;
    double left = *at - nc_lua_now();
    return left > 0 ? left : 0;
}

lua_State* nc_lua_newstate(NCLuaMemTracker *tracker, size_t max_bytes) {
    if (tracker != NULL) {
        tracker->current_bytes = 0;
        tracker->peak_bytes = 0;
        tracker->max_bytes = max_bytes;
    }
    lua_State *L = lua_newstate(nc_lua_alloc, tracker);
    if (L != NULL) {
        luaL_openlibs(L);
        lua_gc(L, LUA_GCGEN, 0, 0); /* generational GC: session garbage dies young (S1 §2.3) */
    }
    return L;
}

void nc_lua_close(lua_State *L) {
    if (L == NULL) return;
    lua_getfield(L, LUA_REGISTRYINDEX, NC_DEADLINE_KEY);
    void *at = lua_touserdata(L, -1);
    lua_pop(L, 1);
    free(at);
    lua_close(L);
}

int nc_lua_load_string(lua_State *L, const char *code, size_t len, const char *chunkname) {
    if (L == NULL || code == NULL) return LUA_ERRERR;
    const char *name = chunkname ? chunkname : "chunk";
    return luaL_loadbufferx(L, code, len, name, NULL);
}

int nc_lua_pcall(lua_State *L, int nargs, int nresults) {
    if (L == NULL) return LUA_ERRERR;
    return lua_pcallk(L, nargs, nresults, 0, 0, NULL);
}

const char* nc_lua_get_error(lua_State *L) {
    if (L == NULL) return "null state";
    const char *err = lua_tolstring(L, -1, NULL);
    return err ? err : "unknown lua error";
}

void nc_lua_set_context_ptr(lua_State *L, void *ptr) {
    if (L == NULL) return;
    lua_pushlightuserdata(L, ptr);
    lua_setfield(L, LUA_REGISTRYINDEX, "_nc_session_ptr");
}

void* nc_lua_get_context_ptr(lua_State *L) {
    if (L == NULL) return NULL;
    lua_getfield(L, LUA_REGISTRYINDEX, "_nc_session_ptr");
    void *ptr = lua_touserdata(L, -1);
    lua_pop(L, 1);
    return ptr;
}

void nc_lua_register_fn(lua_State *L, const char *table_name, const char *fn_name, lua_CFunction fn) {
    if (L == NULL || fn_name == NULL || fn == NULL) return;
    if (table_name != NULL && strlen(table_name) > 0) {
        lua_getglobal(L, table_name);
        if (lua_type(L, -1) != LUA_TTABLE) {
            lua_pop(L, 1);
            lua_newtable(L);
            lua_pushvalue(L, -1);
            lua_setglobal(L, table_name);
        }
        lua_pushcfunction(L, fn);
        lua_setfield(L, -2, fn_name);
        lua_pop(L, 1); /* pop table */
    } else {
        lua_pushcfunction(L, fn);
        lua_setglobal(L, fn_name);
    }
}

void nc_lua_push_bytes(lua_State *L, const char *bytes, size_t len) {
    if (L == NULL) return;
    if (len == 0) {
        lua_pushlstring(L, "", 0);
    } else if (bytes == NULL) {
        lua_pushnil(L);
    } else {
        lua_pushlstring(L, bytes, len);
    }
}

const char* nc_lua_get_bytes(lua_State *L, int idx, size_t *out_len) {
    if (L == NULL) return NULL;
    return lua_tolstring(L, idx, out_len);
}

void nc_lua_push_closure(lua_State *L, lua_CFunction fn, void *upvalue) {
    if (L == NULL || fn == NULL) return;
    lua_pushlightuserdata(L, upvalue);
    lua_pushcclosure(L, fn, 1);
}

void* nc_lua_upvalue_ptr(lua_State *L) {
    if (L == NULL) return NULL;
    return lua_touserdata(L, lua_upvalueindex(1));
}

#define NC_CTX_KEY "nc_ctx_table"

void nc_lua_init_context(lua_State *L) {
    if (L == NULL) return;
    lua_newtable(L);
    lua_pushvalue(L, -1);
    lua_setfield(L, LUA_REGISTRYINDEX, NC_CTX_KEY);
    lua_pop(L, 1);
}

void nc_lua_push_context(lua_State *L) {
    if (L == NULL) return;
    lua_getfield(L, LUA_REGISTRYINDEX, NC_CTX_KEY);
}

static void nc_lua_ensure_table(lua_State *L, const char *t1, const char *t2) {
    lua_getglobal(L, t1);
    if (lua_type(L, -1) != LUA_TTABLE) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setglobal(L, t1);
    }
    if (t2 != NULL) {
        lua_getfield(L, -1, t2);
        if (lua_type(L, -1) != LUA_TTABLE) {
            lua_pop(L, 1);
            lua_newtable(L);
            lua_pushvalue(L, -1);
            lua_setfield(L, -3, t2);
        }
        lua_remove(L, -2); /* drop t1, keep t1.t2 on top */
    }
}

void nc_lua_register_nested(lua_State *L, const char *t1, const char *t2, const char *fn_name, lua_CFunction fn) {
    if (L == NULL || t1 == NULL || fn_name == NULL || fn == NULL) return;
    nc_lua_ensure_table(L, t1, t2);
    lua_pushcfunction(L, fn);
    lua_setfield(L, -2, fn_name);
    lua_pop(L, 1);
}

void nc_lua_set_table_int(lua_State *L, const char *t1, const char *t2, const char *field, long long v) {
    if (L == NULL || t1 == NULL || field == NULL) return;
    nc_lua_ensure_table(L, t1, t2);
    lua_pushinteger(L, (lua_Integer)v);
    lua_setfield(L, -2, field);
    lua_pop(L, 1);
}

void nc_lua_set_table_string(lua_State *L, const char *t1, const char *t2, const char *field, const char *v) {
    if (L == NULL || t1 == NULL || field == NULL) return;
    nc_lua_ensure_table(L, t1, t2);
    lua_pushstring(L, v ? v : "");
    lua_setfield(L, -2, field);
    lua_pop(L, 1);
}

void nc_lua_set_table_bool(lua_State *L, const char *t1, const char *t2, const char *field, int v) {
    if (L == NULL || t1 == NULL || field == NULL) return;
    nc_lua_ensure_table(L, t1, t2);
    lua_pushboolean(L, v ? 1 : 0);
    lua_setfield(L, -2, field);
    lua_pop(L, 1);
}
