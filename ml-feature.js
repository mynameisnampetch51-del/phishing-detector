const ml_feature = [
  { name: "URLLength", weight: -0.7137504525486724, mean: 34.58409317415552, std: 40.9775247711013 },
  { name: "DomainLength", weight: 2.0486374654450996, mean: 21.47520091604996, std: 9.167343009572425 },
  { name: "IsDomainIP", weight: -0.12128393895692918, mean: 0.002788439110244068, std: 0.05273199899086444 },
  { name: "CharContinuationRate", weight: -1.5685698925263427, mean: 0.8451829934721368, std: 0.21680503817672908 },
  { name: "TLDLegitimateProb", weight: -0.2760502499890737, mean: 0.2600782329316779, std: 0.2516099498815318 },
  { name: "URLCharProb", weight: 1.356649134662874, mean: 0.05573691035771539, std: 0.010599202897383633 },
  { name: "TLDLength", weight: -0.33804734217920035, mean: 2.7647055705167625, std: 0.6007439034157412 },
  { name: "NoOfSubDomain", weight: 1.1237793791601494, mean: 1.1657636930384445, std: 0.6018119366082341 },
  { name: "HasObfuscation", weight: -0.2670130314572293, mean: 0.002040967789817426, std: 0.04513094548420578 },
  { name: "NoOfObfuscatedChar", weight: -0.035737374141292966, mean: 0.02673402743908904, std: 2.0821848262660927 },
  { name: "ObfuscationRatio", weight: -0.16822103732841476, mean: 0.00013709472211030768, std: 0.003816621845326634 },
  { name: "NoOfLettersInURL", weight: -1.852204126691179, mean: 19.42078924489493, std: 27.80534257678066 },
  { name: "LetterRatioInURL", weight: -4.8259957566184095, mean: 0.5157902097160668, std: 0.12329606503659755 },
  { name: "NoOfDegitsInURL", weight: -0.9854360840237872, mean: 1.8913515977862125, std: 12.584412125518801 },
  { name: "DegitRatioInURL", weight: -4.016049212117721, mean: 0.028708661125129886, std: 0.07098549894524354 },
  { name: "NoOfEqualsInURL", weight: -0.12575207621920315, mean: 0.06391144850399712, std: 1.009737266942173 },
  { name: "NoOfQMarkInURL", weight: -0.34161906782425444, mean: 0.029591382344833436, std: 0.19431830920274554 },
  { name: "NoOfAmpersandInURL", weight: -0.06311745543440671, mean: 0.02583282088254628, std: 0.8948369943059007 },
  { name: "NoOfOtherSpecialCharsInURL", weight: -2.1394469591555683, mean: 2.345904281261265, std: 3.6838640979042903 },
  { name: "SpacialCharRatioInURL", weight: -3.8168112820638807, mean: 0.06335229754659769, std: 0.03238087499611005 },
  { name: "IsHTTPS", weight: 7.164181048574509, mean: 0.7826395809919634, std: 0.41244983604880653 },
  { name: "LineOfCode", weight: 2.556940466588761, mean: 1140.6745637100023, std: 3520.0540833580444 },
  { name: "LargestLineLength", weight: -2.444772104698618, mean: 12855.458804257936, std: 153530.41771756773 },
  { name: "HasTitle", weight: 1.841263731111129, mean: 0.8611664793570687, std: 0.34577272042314167 },
  { name: "DomainTitleMatchScore", weight: 1.0541463197989125, mean: 50.09008115353439, std: 49.673857082366325 },
  { name: "URLTitleMatchScore", weight: -0.7399573926833167, mean: 52.062632792476016, std: 49.60023698442647 },
  { name: "HasFavicon", weight: 0.34888138519240525, mean: 0.36192985432261077, std: 0.48055866954267357 },
  { name: "Robots", weight: 0.041565305181429944, mean: 0.2667677431667338, std: 0.4422699564434163 },
  { name: "IsResponsive", weight: 0.29812142746395837, mean: 0.6248595178014801, std: 0.4841591688839342 },
  { name: "NoOfURLRedirect", weight: -0.2455772856933916, mean: 0.13369134205559915, std: 0.34032038892045824 },
  { name: "NoOfSelfRedirect", weight: 0.3894682624424048, mean: 0.03975381157361267, std: 0.1953802601057291 },
  { name: "HasDescription", weight: 1.2380666237656326, mean: 0.4401015712801374, std: 0.4963992125667521 },
  { name: "NoOfPopup", weight: 0.6645351082003198, mean: 0.22479802370703364, std: 4.027249814255051 },
  { name: "NoOfiFrame", weight: 0.5337466670023542, mean: 1.582280158612354, std: 5.871171271616065 },
  { name: "HasExternalFormSubmit", weight: -0.004407860197945118, mean: 0.04410610912021035, std: 0.20533085559283693 },
  { name: "HasSocialNet", weight: 2.172485359607556, mean: 0.4563497953730995, std: 0.49809101541387973 },
  { name: "HasSubmitButton", weight: 0.270905555914433, mean: 0.4149154986322865, std: 0.49270744628735574 },
  { name: "HasHiddenFields", weight: 0.6198409888793835, mean: 0.3775366313959159, std: 0.4847707946546907 },
  { name: "HasPasswordField", weight: -0.21858570328610594, mean: 0.10231345024279564, std: 0.3030600734874369 },
  { name: "Bank", weight: -0.037156706221279666, mean: 0.12695879895672088, std: 0.3329268122638785 },
  { name: "Pay", weight: 0.4810117020456666, mean: 0.23749443372420959, std: 0.42554767967200413 },
  { name: "Crypto", weight: -0.14806157376049056, mean: 0.02341546682499629, std: 0.15121898934447284 },
  { name: "HasCopyrightInfo", weight: 1.371763838015476, mean: 0.4872876863377086, std: 0.4998383709574041 },
  { name: "NoOfImage", weight: 2.9900440769054053, mean: 25.91728514175449, std: 76.23460819017649 },
  { name: "NoOfCSS", weight: 0.9325932992036989, mean: 6.379180008057847, std: 83.49769944387386 },
  { name: "NoOfJS", weight: 3.70699396112735, mean: 10.523171610933225, std: 23.507656720613475 },
  { name: "NoOfSelfRef", weight: 3.7371406341315576, mean: 64.75628193982061, std: 154.89910921100207 },
  { name: "NoOfEmptyRef", weight: 0.7247326105739872, mean: 2.393313047350453, std: 18.493835655036825 },
  { name: "NoOfExternalRef", weight: 3.136420166756021, mean: 48.94418880807481, std: 140.59451504817972 },
];
const ml_intercept = 1.8503170263297255;

function predictML(featureValues) {
  let score = 0;
  for (const f of ml_feature) {
    const raw = featureValues[f.name];
    const scaled = (raw - f.mean) / f.std;
    score += scaled * f.weight;
  }
  score += ml_intercept;
  const probability = 1 / (1 + Math.exp(-score));
  return probability;
}