local policy = dofile("lib/password_policy.lua")

assert(policy.validate("Abc123!x"))
assert(policy.validate("A1!aaaaa"))
assert(not policy.validate("A1!"))
assert(not policy.validate("Abc12345"))
assert(not policy.validate("abcdefgh!"))
assert(not policy.validate("12345678!"))
print("PASSWORD_POLICY_OK")
