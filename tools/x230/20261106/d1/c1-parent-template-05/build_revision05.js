(function build(previousParent, previousSealer, previousInstaller) {
  const parentChanges = [
  [
    "ROOT / \"ordinary-tools-01/verify_ordinary_01.py\"",
    "ROOT / \"ordinary-tools-02/verify_ordinary_02.py\""
  ],
  [
    "ROOT / \"ordinary-verification-input-01.json\"",
    "ROOT / \"ordinary-verification-input-02.json\""
  ],
  [
    "ROOT / \"ordinary-postflight-01.json\"",
    "ROOT / \"ordinary-postflight-02.json\""
  ],
  [
    "\"hepta-d1-ordinary-supplement-validation/v2\"",
    "\"hepta-d1-ordinary-supplement-validation/v3\""
  ],
  [
    "\"hepta-d1-ordinary-supplement-postflight/v2\"",
    "\"hepta-d1-ordinary-supplement-postflight/v3\""
  ],
  [
    "ROOT / \"ordinary-01\" / name",
    "ROOT / \"ordinary-02\" / name"
  ]
];
  let parent = previousParent;
  for (const [before, after] of parentChanges) {
    if (parent.split(before).length !== 2) throw new Error("nonunique parent anchor");
    parent = parent.replace(before, after);
  }
  const before = 'sources["ordinary/verify_ordinary_01.py"]';
  const after = 'sources["ordinary/verify_ordinary_02.py"]';
  if (previousSealer.split(before).length !== 2) throw new Error("nonunique sealer anchor");
  return {parent, sealer: previousSealer.replace(before, after), installer: previousInstaller};
})
