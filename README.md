# overview

this is a hack of a script to convert junos filters to IOSXR.  this is pretty crude in terms of being able to parse the juniper configuration.  it only parses a single filter at a time so you're going to want to break the junos config out to separate filters.


## 'except' keyword handling

juniper has the notion of an ACL ```except``` keyword which allows you to pull a more specific prefix out of the terms above. this in turn applies the appropriate inversion for the logic applied for the term overall.

the conversion script will now (naively) prepend the excepted prefixes from the original juniper term and invert the action for these prefixes.  it will handle the src/dst processing appropriately.  honestly, i haven't examined the implications of this behavior in detail.  but for most cases it should do the right thing.

## config parsing anomalies

i just ran across a few ```then``` term anomalies in the original config which the parser doesn't barf on, but are dependent on some additional capabilities (internal objects) which are not incorporated into IOS XR.  these might generate incorrect entries in the final ACL.

## unknown atoms

there are a number of keywords that this doesn't understand.  it will barf an error if it runs across an atom that it doesn't understand.
.
