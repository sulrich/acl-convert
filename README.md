# overview

this is a hack of a script to convert junos filters to IOSXR.  this is pretty crude in terms of being able to parse the juniper configuration.  it only parses a single filter at a time so you're going to want to break the junos config out to separate filters.


## 'except' keyword handling

juniper has the notion of an ACL ```except``` keyword which allows you to pull a more specific prefix out of the terms above. this in turn applies the appropriate inversion for the logic applied for the term overall.  i don't do anything intelligent with 'except' keywords .  this needs to get busted out separately.

## config parsing anomalies

i just ran across a few ```then``` term anomalies in the original config which the parser doesn't barf on, but are dependent on some additional capabilities (internal objects) which are not incorporated into IOS XR.  these might generate incorrect entries in the final ACL.

## unknown atom
.
