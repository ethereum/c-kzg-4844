--styleCheck:usages
# nimyaml style will error
--styleCheck:hint

# checkAbi support at the time of writing is limited to linux - this may change
# with Nim 2.4.
when defined(linux):
  --define:"checkAbi"
