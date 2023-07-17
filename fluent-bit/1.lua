local json = require("dkjson")

-- Your Lua table

a = {
    1 = {key1 = "val1"},
    2 = {key2 = "val2"},
    3 = {key3 = "val3"}
}

-- Convert Lua table to JSON
s = json.decode(a)
print(s)
