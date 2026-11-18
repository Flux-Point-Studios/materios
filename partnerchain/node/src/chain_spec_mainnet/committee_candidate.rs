//! The scripts a partner chain's genesis UTXO parameterises: the committee
//! candidate validator, whose address the follower reads registrations at,
//! and the D-parameter and permissioned candidates policies, whose tokens
//! mark the outputs it reads the committee's inputs from.
//!
//! partner-chains v1.8.0, which sets the chain up on Cardano, applies each
//! script to its parameters as aiken's `uplc` applies Plutus data to a
//! program, and hashes the applied script as a Plutus V2 script. Every
//! script takes the genesis UTXO. The D-parameter and permissioned
//! candidates scripts then take the version oracle policy's id, and each
//! policy the address of its validator.

use hex_literal::hex;

/// `COMMITTEE_CANDIDATE_VALIDATOR` of partner-chains-smart-contracts v8.1.0
/// (`raw-scripts/src/lib.rs`), the release partner-chains v1.8.0 pins: a CBOR
/// byte string holding a flat-encoded UPLC program.
const COMMITTEE_CANDIDATE_VALIDATOR: [u8; 177] = hex!(
    "58af0100002222533533223535323233322212333001004003002375c6ae84008d5d08009bad357426ae88004d"
    "5d10009bac005222123330010040030022322253355335300337586ae84d5d11aba2357446ae88d5d11aba2357"
    "446ae88d55cf1baa357426aae78dd500390803880288030802991800800912999aab9f00111220011325335333"
    "573466e3c0100040180144488c00800c4c8cc010010004d5d10011bae357420022440042440022930b01"
);

/// `VERSION_ORACLE_VALIDATOR`, which holds the versions of the chain's scripts.
const VERSION_ORACLE_VALIDATOR: [u8; 1791] = hex!(
    "5906fc010000332232323232332222225335323235002223233223232323232323232323232323253353335734"
    "66e1d200235573a6ea8d5d09aba200102001f13253355335533532533553353300f3752a66a664600200244a66"
    "a002203c442646660166ae84d5d11aab9e3754006444464a66a666ae68cdc3a40086aae740040b00ac54cd4008"
    "84cc8c004004894cd40044024884c94cd400c84d4004894cd4cc0cc009204015335333573466e1d20023330210"
    "0d0264890e56657273696f6e206f7261636c6500035034133502e0090041004100410013300400400132335027"
    "00102832333333357480024a03a4a03a46466660404a03e444a66a66666606044a0464a0444a04442446004006"
    "4a0440064266660484a046444a66a66666606844a04e4a04c4a04c4a04c4244600400600642666605042446004"
    "246600201200a444a0520060442a04a00603c2a0420020346eb00089407494074060d5d09aab9e002100610063"
    "754004400466008008002664600200246602603a4466a03c004660060060026464664600200246602a0044466a"
    "e80008cc00c00c004008cc00c88888888888803098cc00888888888888802c98588854cd40044008885800484c"
    "048dd58008a808109809199180080091980a00f1119a80f999109198008018011bae35573a0046eb4d55cf0011"
    "98018018008008a808198009111111111110041310a99a80088109109a80111299a8018999ab9a337120029000"
    "0128131108138810081088100a99aa99a9980f80980a081088100a99a980199800911111111111005130810881"
    "00810081018019aba10011635573c6ea8050c8c00400488ccc040080894cd54cd4c8c8c8c94cd4cc084d5d0801"
    "1aba100113253353001357426ae8800c854cd4c008d5d09aba20032132532335333573466e1d200035573a0040"
    "56054264a66a666ae68cdc3a40006aae740040b00ac4cc09cd5d09aab9e003357426aae780044c009263754006"
    "26002931199813802111199815003111299a999ab9a3370e00c0060620602a66a666ae68cdc380280101881809"
    "99ab9a3370e00800206206020602060405c40566ea8008409c54cd4c004d5d09aba2002210271027300b200110"
    "2535573c6ea8008d55cf1baa002533532333007357420024444444444446464a66a666ae68cdc3a40046aae740"
    "080c80c44c00403854080c8c00400488ccc08d4084894cd4c8c94cd4ccd5cd19b8f301f002301f001037036133"
    "3573466e1cc088008c0880040dc0d840d8d5d09aab9e006357426aae78dd500108911801002099802002000800"
    "9baa357426ae880349404cd55cf1baa01821333008357426ae88d55cf1baa00100b00a16333006002009008102"
    "21333573466e24ccc038dd59aba1357446aae78dd5001009a4410e56657273696f6e206f7261636c6500480000"
    "880844cc0100100044084004888c8c8c8c8c8c8c8c8c8c8c8cccccccccccc034dd61aba100b37586ae84028dd6"
    "1aba100937566ae84020dd59aba100737586ae84018dd59aba1005357420086eb0d5d08019bab357420046eacd"
    "5d0800980a1aba1357440026ae88004d5d10009aba2001357440026ae88004d5d10009aba2001357440026ae88"
    "004d5d10009aab9e3754006444646464666600a6ae8400cdd59aba1002357420026600eeb8d5d09aba20013574"
    "40026ae88004d55cf1baa003223232325335333573466e1d200200202001f1500e15335333573466e1d2000002"
    "02001f1300f3005357420022c6aae78008d55ce8009baa00126222200423002357426aae78dd50009191919299"
    "a999ab9a3370e900000100d80d09bae357420022c6aae78008d55ce8009baa001120012375a6ae84d5d11aab9e"
    "375400244466a660086ea400800c8c8cd4cc018dd480180091bad00148000dd5800a400044664600200246600c"
    "a0084a66a666ae68cdd78021aab9d00101701612300735573c0042466006006002002424460040062244002444"
    "a666aae7c004400c4cc008d5d08009aba2001375a0066a64664424660020060046eb4d5d08009bae357426ae88"
    "004dd60019109198008018010a4c2c244004244244660020080064464a6466a666ae68cdc3a40006aae7400802"
    "40204c94cd4ccd5cd19b8748000d55ce8008050048999ab9a3371e6eb8d5d09aab9e003375c6ae84d55cf00080"
    "50048980124c6ea800c4c0052625335333573466e1d200235573a004012010264a66a666ae68cdc3a40046aae7"
    "40040280244ccd5cd19b8f375c6ae84d55cf0019bae357426aae780040280244024dd500188041baa002222325"
    "335333573466e1d200235573a00201000e2646466600a6eb4d5d08011bad357420026eb4d5d09aba2001357440"
    "026aae780044c009263754006444444a666666ae900044c8cc01cd55ce8009aab9e00137540022600a6eac0044"
    "c010dd6000898019bad00113002375c00244666ae68cdc38010008020018910010910009"
);

/// `VERSION_ORACLE_POLICY`, whose tokens mark those versions.
const VERSION_ORACLE_POLICY: [u8; 2530] = hex!(
    "5909df010000332232323322323232323232332223232323232323232323232323232323232222533532323232"
    "5335333573466e1d200035573a00204e04c2646464666a00e464a66a6602a4c664600200244a66a00220444426"
    "466602c6ae84d5d11aab9e3754006444466605a0044a66a6464a66a6605a6ae84008d5d0800899299a98009aba"
    "13574400642a66a60046ae84d5d1001909929919a999ab9a3370e90001aab9d00203d03c1325335333573466e1"
    "d200035573a00207c07a2660666ae84d55cf0019aba135573c00226004931baa003130014988ccc0cc010888cc"
    "c0d80188894cd4ccd5cd19b8700600304304215335333573466e1c01400810c1084ccd5cd19b87004001043042"
    "104210422040203d375400420722a66a60026ae84d5d10011081c881c980f017881b9aab9e375402e6aae78dd5"
    "002899199180080091299a800880491099299a801909a80091299a9981e80100a8a99a9981e99981300680c245"
    "0e56657273696f6e206f7261636c6500480084cc0240fc010401040104004cc010010004cc004c0c00080ad40a"
    "4401880188008cc010010004c004ccc06801c06005c54cd54cd54cd4cc8c004004894cd40044088884c94cd4cc"
    "d5cd19b8933301837566ae84d5d11aab9e375400601491010e56657273696f6e206f7261636c6500480000c00c"
    "44cd40900ac0044004cc010010004c004c06401c40b08840b440b040ac54cd4cc03801402840b040ac40ac40ac"
    "c054088894cd54cd4c034ccc06801c06005c40b040ac54cd4cc05498cc01000800454cd5400c40b040ac40ac40"
    "ac894cd4cc05498cc01000800454cd54cd4cc03801402840b040ac54cd5400c40b040ac40ac40ac4cc09cccc04"
    "0ccc05c0100340300092210e56657273696f6e206f7261636c65004800888cc8c004004894cd40044080884c8c"
    "cc05000c8888ccc0ac00894cd4008854cd4c8c94cd4cc0b0d5d08011aba100113253353001357426ae8800c854"
    "cd4c008d5d09aba20032132532335333573466e1d200035573a004078076264a66a666ae68cdc3a40006aae740"
    "040f40f04cc0c8d5d09aab9e003357426aae780044c0092637540062600293119981900211119981a803111299"
    "a999ab9a3370e00c0060840822a66a666ae68cdc38028010210208999ab9a3370e00800208408220822082407e"
    "40786ea800840e054cd4c004d5d09aba2002210381038301d02e103635573c6ea8058d55cf1baa006132332300"
    "1001225335001100a22132533500321350012253353303c00201615335333573466e3c0280540f80f454cd4cc0"
    "f0ccc09403805d22010e56657273696f6e206f7261636c6500480084cc0240f80104010401040104004cc01001"
    "0004cc004c0bc00c0a940a0401c401880188008cc010010004cc050084c05c014dd71aba135573c0022c6ea8d5"
    "d09aba2002357420026aae78dd5001191919299a999ab9a3370e9000001013012899910911198010028021bad3"
    "57420026eb8d5d09aba200115335333573466e1d200200202602513322122233001005004375a6ae84004dd71a"
    "ba1357440022a66a666ae68cdc3a400800404c04a264244460060086eb4d5d08008b1aab9e00235573a0026ea8"
    "008526163230010012233301e020225335325335333573466e3cc04c058c04c00409008c4ccd5cd19b87301501"
    "630150010240231023357426aae78dd500108118998020020008009119299a99299aa99a998051ba9533533230"
    "0100122533500110182213233300c357426ae88d55cf1baa0032222325335333573466e1d200435573a0020580"
    "562a66a0044264664600200244a66a002201444264a66a006426a00244a66a6606800490200a99a999ab9a3370"
    "e900119980e80700c2450e56657273696f6e206f7261636c650003603513300900a00410041004100133004004"
    "001330013027357426aae7800c089408040184018dd5001100119802002000999180080091981000b9119a80c0"
    "01198018018009991800800919810198018078071119aba0002330030030013300222222222222200b26162215"
    "3350011002221600121301f37560022a03a42603e66460020024660420304466a032664424660020060046eb8d"
    "55ce8011bad35573c004660060060020022a03a6600200a00842a66a00220424426a00444a66a0062666ae68cd"
    "c4800a400004a04c44204e2040601c6ae84d55cf1baa001262222222222220082223232323333005357420066e"
    "acd5d08011aba10013300775c6ae84d5d10009aba2001357440026aae78dd500191191919299a999ab9a3370e9"
    "00100100f80f0a80d0a99a999ab9a3370e900000100f80f0980d98029aba10011635573c0046aae74004dd5000"
    "91119a998021ba900200323233533006375200600246eb400520003756002900011199180080091980c280b129"
    "9a999ab9a3375e0086aae7400407006c48c064d55cf001091980180180080091299a80089801009910a99a8008"
    "801110980300b919180080091980a8061119a80698020011980180180093111111111111006119980100091111"
    "11111110051311119191919191919191919191999999999998069bac357420166eb0d5d08051bac357420126ea"
    "cd5d08041bab3574200e6eb0d5d08031bab3574200a6ae84010dd61aba100337566ae84008dd59aba100130103"
    "57426ae88004d5d10009aba2001357440026ae88004d5d10009aba2001357440026ae88004d5d10009aba20013"
    "5573c6ea800c8c008d5d09aab9e37540024646464a66a666ae68cdc3a400000402802626eb8d5d08008b1aab9e"
    "00235573a0026ea80048dd69aba1357446aae78dd500089100109109119800802001911929919a999ab9a3370e"
    "90001aab9d00200f00e1325335333573466e1d200035573a00202001e2666ae68cdc79bae357426aae7800cdd7"
    "1aba135573c00202001e26004931baa0031300149894cd4ccd5cd19b8748008d55ce801007807099299a999ab9"
    "a3370e90011aab9d00101000f1333573466e3cdd71aba135573c0066eb8d5d09aab9e00101000f100f37540062"
    "01c6ea8008888c94cd4ccd5cd19b8748008d55ce800807006899191998029bad357420046eb4d5d08009bad357"
    "426ae88004d5d10009aab9e00113002498dd5001900091119299a999ab9a3370e90021aab9d00100c00b130033"
    "57426aae780044c00926375400646666666ae9000494010940108c8cccc01c940188894cc8d4cccccc00489402"
    "c94028940288488c00800c9402801084cccc0309402c8894cd4cccccc01489403c9403894038940388488c0080"
    "0c00c84cccc0408488c00848cc004024014889404400c034540340100248888894cccccd5d2000899198039aab"
    "9d00135573c0026ea80044c014dd5800898021bac00113003375a002260046eb800454020004010dd600112802"
    "12802001090009091180100188910009112999aab9f0011003133002357420026ae8800488ccd5cd19b8700200"
    "10040031220021220011"
);

/// `D_PARAMETER_VALIDATOR`, which holds the D-parameter.
const D_PARAMETER_VALIDATOR: [u8; 891] = hex!(
    "59037801000033223233222222253355335323232323322325335330013752a66a64664600200244a66a002202"
    "244264646464a66a666ae68cdc3a40086aae7400406806454cd4c8c8c94cd4ccd5cd19b8748008008074070540"
    "3854cd4ccd5cd19b87480000080740704c03cdd71aba10011635573c0046aae74004dd51aba13574400442a66a"
    "646666666ae9000494038940388c8cccc044940408894cd4cccccc07c8940509404c9404c8488c00800c9404c0"
    "0c84cccc054940508894cd4cccccc08c8940609405c9405c9405c8488c00800c00c84cccc0648488c00848cc00"
    "4024014889406800c0545405800c04454048004034dd600112807128070059aba135573c004426a00244a66a66"
    "6ae68cdc3a408000403c03a2a66a666ae68cdc3a400466a6601c6ea4050dd59aba1007232335330104c10f4e56"
    "657273696f6e206f7261636c65000012375a00290001bab001480000780744cd40680100204020402040144010"
    "4010dd51aba1001357440026ae88d55cf1baa357426ae88d55cf1baa0033300400400133230010012330060102"
    "233501100233003003001323233230010012330080022233574000466006006002004660104444444444440184"
    "c6600e4444444444440164c240022c442a66a0022004442c00a42a66a64664600200246600e0224466a0246644"
    "24660020060046eb8d55ce8011bad35573c004660060060020026eac0044044884d4008894cd400c4ccd5cd19b"
    "890014800005405888405c404088cc8c0040048cc019401094cd4ccd5cd19baf00435573a00202802624600e6a"
    "ae7800848cc00c00c0040048488c00800c44880048894ccd55cf80088018998011aba100135744002660024444"
    "444444440104c6444646464646464646464646466666666666601a6eb0d5d08059bac357420146eb0d5d08049b"
    "ab357420106eacd5d08039bac3574200c6eacd5d08029aba100437586ae8400cdd59aba100237566ae84004c8c"
    "8c94cd4ccd5cd19b874800000807006c4dd71aba10011635573c0046aae74004dd51aba1357440026ae88004d5"
    "d10009aba2001357440026ae88004d5d10009aba2001357440026ae88004d5d10009aab9e37540066ae84d55cf"
    "1baa002375c008201420122930b091001091091198008020019111112999999aba40011323300735573a0026aa"
    "e78004dd5000898029bab001130043758002260066eb40044c008dd70008910010910009"
);

/// `D_PARAMETER_POLICY`, whose token marks the D-parameter.
const D_PARAMETER_POLICY: [u8; 1566] = hex!(
    "59061b0100003233223222222533533223232325335333573466e1d200035573a00200a008264a666446464646"
    "464646aa66aa66a660066ea54cd4c8c8cc8c004004894cd40044068884c8ccc030d5d09aba235573c6ea800c88"
    "88c94cd4ccd5cd19b8748010d55ce80080d00c8a99a80110a99a991999999aba40012501625016232333301425"
    "018222533533333301222501c2501b2501b212230020032501b0032133330182501c2225335333333016225020"
    "2501f2501f2501f2122300200300321333301c21223002123300100900522250220030181501e0030141501a00"
    "101037580044a02c4a02c01c6ae84d55cf001109a80091299a999ab9a3370e902000100f00e8a99a999ab9a337"
    "0e900119a998099ba901c008232335330154c10f4e56657273696f6e206f7261636c65000012375a00290001ba"
    "b001480000780744cd409401002840284028401c40184018dd5001100119802002000999180080091980380c91"
    "19a80d00119801801800999180080091980399802911111111111006131119aba0002330030030013300422222"
    "222222200b26222222533333357480022646600e6aae74004d55cf0009baa001130053756002260086eb00044c"
    "00cdd6800898011bae001120011622153350011002221600121533533230010012330060182233501933221233"
    "001003002375c6aae74008dd69aab9e002330030030013756002201c4426a00444a66a0062666ae68cdc4800a4"
    "000024026442028201a201c201a2a66a666ae68c8cdc399800801005180a9919199180080091299a800880d910"
    "99299a9919299a998041aba100235742002264a66a60026ae84d5d100190a99a98011aba1357440064264a6466"
    "a666ae68cdc3a40006aae740080740704c94cd4ccd5cd19b8748000d55ce80080f00e8998071aba135573c0066"
    "ae84d55cf0008980124c6ea800c4c00526233300e0042223330110062225335333573466e1c01800c08c08854c"
    "d4ccd5cd19b870050020230221333573466e1c01000408c0884088408880808074dd5001080c8a99a98009aba1"
    "3574400442032203260204002202e6aae78dd500d1aab9e375466601a00644440084c266a03a660106eacd5d09"
    "aba235573c6ea800c0440044004cc010010004cc8c0040048cc02006888cd406c008cc00c00c004cc014888888"
    "8888880289888c94c8cd4ccd5cd19b8748000d55ce80100a009899299a999ab9a3370e90001aab9d0010150141"
    "333573466e3cdd71aba135573c0066eb8d5d09aab9e00101501413002498dd500189800a4c4a66a666ae68cdc3"
    "a40046aae7400805004c4c94cd4ccd5cd19b8748008d55ce80080a80a0999ab9a3371e6eb8d5d09aab9e003375"
    "c6ae84d55cf00080a80a080a1baa0031013375400444464a66a666ae68cdc3a40046aae7400404c0484c8c8ccc"
    "014dd69aba1002375a6ae84004dd69aba1357440026ae88004d55cf0008980124c6ea800c88cd4cc014dd48008"
    "0111991800800919804240004466e00dd69aab9e00233003003001375600290000070068807080699800911111"
    "111111004131119191919191919191919191999999999998069bac357420166eb0d5d08051bac357420126eacd"
    "5d08041bab3574200e6eb0d5d08031bab3574200a6ae84010dd61aba100337566ae84008dd59aba10013232325"
    "335333573466e1d200000201c01b1375c6ae8400458d55cf0011aab9d00137546ae84d5d10009aba2001357440"
    "026ae88004d5d10009aba2001357440026ae88004d5d10009aba2001357440026aae78dd51aba100b223323001"
    "001233004500725335333573466ebc010d55ce8008078070918051aab9e002123300300300100122253335573e"
    "00220062660046ae84004d5d100091119191919998029aba100337566ae84008d5d080099803bae357426ae880"
    "04d5d10009aba200135573c6ea800c88c8c8c94cd4ccd5cd19b87480080080340305401854cd4ccd5cd19b8748"
    "0000080340304c01cc014d5d08008b1aab9e00235573a0026ea80048488c00800c44880044014dd71aba135573"
    "c0022c6ea8d5d09aba200135573c6ea8010dd70030910010910008a4c2c64600200244a66a0022600a44002442"
    "66600e4400400466008008002244004244244660020080064660024466e0000800520001"
);

/// `PERMISSIONED_CANDIDATES_VALIDATOR`, which holds the permissioned candidates.
const PERMISSIONED_CANDIDATES_VALIDATOR: [u8; 955] = hex!(
    "5903b8010000332232332222222533532532335325335333573466e1d200000100d00c11220011533533357346"
    "6e1d200200100d00c112200216375a0082a66a66002004006201820162a66a6600200400620182016446464646"
    "64464a66a660026ea54cd4c8cc8c004004894cd4004404c884c8c8c8c94cd4ccd5cd19b8748010d55ce80080e0"
    "0d8a99a991919299a999ab9a3370e900100100f80f0a8070a99a999ab9a3370e900000100f80f098079bae3574"
    "20022c6aae78008d55ce8009baa357426ae88008854cd4c8ccccccd5d200092807128071191999808928081112"
    "99a99999981091280a1280992809909118010019280980190999980a9280a111299a99999981291280c1280b92"
    "80b9280b9091180100180190999980c909118010919800804802911280d00180a8a80b0018088a8090008069ba"
    "c0022500e2500e00b357426aae7800884d4004894cd4ccd5cd19b874810000808007c54cd4ccd5cd19b8748008"
    "cd4cc038dd480a9bab3574200e46466a660209810f4e56657273696f6e206f7261636c65000012375a00290001"
    "bab0014800008007c4cd407001002040204020401440104010dd51aba1001357440026ae88d55cf1baa357426a"
    "e88d55cf1baa003330040040013323001001233006012223350130023300300300132323323001001233008002"
    "2233574000466006006002004660104444444444440184c6600e4444444444440164c240022c442a66a0022004"
    "442c00a42a66a64664600200246600e0264466a028664424660020060046eb8d55ce8011bad35573c004660060"
    "060020026eac004404c884d4008894cd400c4ccd5cd19b890014800005c060884064404888cc8c0040048cc019"
    "401094cd4ccd5cd19baf00435573a00202c02a24600e6aae7800848cc00c00c0040048488c00800c4488004889"
    "4ccd55cf80088018998011aba100135744002660024444444444440104c6444646464646464646464646466666"
    "666666601a6eb0d5d08059bac357420146eb0d5d08049bab357420106eacd5d08039bac3574200c6eacd5d0802"
    "9aba100437586ae8400cdd59aba100237566ae84004c8c8c94cd4ccd5cd19b87480000080780744dd71aba1001"
    "1635573c0046aae74004dd51aba1357440026ae88004d5d10009aba2001357440026ae88004d5d10009aba2001"
    "357440026ae88004d5d10009aab9e37540066ae84d55cf1baa001375c0082930b0910010910911980080200191"
    "11112999999aba40011323300735573a0026aae78004dd5000898029bab001130043758002260066eb40044c00"
    "8dd70008910010910009"
);

/// `PERMISSIONED_CANDIDATES_POLICY`, whose token marks the permissioned candidates.
const PERMISSIONED_CANDIDATES_POLICY: [u8; 1819] = hex!(
    "590718010000323322332232323232323232323322222225335325323232323232323232323353253353335734"
    "66e1d200000101d01c112200115335333573466e1d200200101d01c112200216375a01a266602e018446660300"
    "024a66aa66a6600801c01e203e203c2a66a666ae68cdc3a40006660122244644600400264600200244a66a0022"
    "0064426600c00466008008002044664600200244a66a002202e44264666042006444466a03a6602000601400a4"
    "0046600800800266014030601800603e03c203e203c203c4c4c266602e018446660300024a66aa66a6600801c0"
    "1e203e203c2a66a666ae68cdc3998039998068018030028009998048891191180100099180080091299a800880"
    "19109980300119802002000811199180080091299a800880b910991998108019111299a9919299a998109aba10"
    "0235742002264a66a60026ae84d5d100190a99a98011aba1357440064264a6466a666ae68cdc3a40006aae7400"
    "80bc0b84c94cd4ccd5cd19b8748000d55ce8008180178998139aba135573c0066ae84d55cf0008980124c6ea80"
    "0c4c00526233302700422233302a0062225335333573466e1c01800c0d40d054cd4ccd5cd19b87005002035034"
    "1333573466e1c0100040d40d040d040d080c880bcdd500108158a99a98009aba13574400442056205660500462"
    "0526aae78dd500d9aab9e3754008266a03a6602000601400a200a40046600800800266014030601800603e03c2"
    "03e203c203c4c4c446464a66a660106ea54cd4c8cc8c004004894cd40044060884c8ccc088d5d09aba235573c6"
    "ea800c8888c94cd4ccd5cd19b8748010d55ce8008150148a99a80110a99a991999999aba40012502e2502e2323"
    "33301a25030222533533333302d2250342503325033212230020032503300321333301e2503422253353333330"
    "3122503825037250372503721223002003003213333022212230021233001009005222503a0030171503600301"
    "31503200100f37580044a05c4a05c01a6ae84d55cf001109a80091299a999ab9a3370e90200010170168a99a99"
    "9ab9a3370e900119a9980b9ba9013008232335330194c10f4e56657273696f6e206f7261636c65000012375a00"
    "290001bab001480000b80b44cd408c01002840284028401c40184018dd50011001198020020009991800800919"
    "80680b9119a80c00119801801800999180080091980699802111111111111006131119aba00023300300300133"
    "00322222222222200b261200116221533500110022216001215335332300100123300d01722335018332212330"
    "01003002375c6aae74008dd69aab9e002330030030013756002203e4426a00444a66a0062666ae68cdc4800a40"
    "0004604844204a203c6600200a00860166ae84d55cf1baa0012622222222222200822335330033752002004466"
    "4600200246601090001119b80375a6aae78008cc00c00c004dd5800a400044664600200246600ca0364a66a666"
    "ae68cdd78021aab9d00101b01a12301e35573c0042466006006002002446466aa006600244004600244002a002"
    "464600200246600601a4466a01c600800466006006002444a666aae7c004400c4cc008d5d08009aba200123330"
    "0200122222222222200a26222323232323232323232323233333333333300d37586ae8402cdd61aba100a37586"
    "ae84024dd59aba100837566ae8401cdd61aba100637566ae84014d5d08021bac357420066eacd5d08011bab357"
    "42002646464a66a666ae68cdc3a400000404604426eb8d5d08008b1aab9e00235573a0026ea8d5d09aba200135"
    "7440026ae88004d5d10009aba2001357440026ae88004d5d10009aba2001357440026ae88004d55cf1baa00337"
    "5c0082930b09100109109119800802001911929919a999ab9a3370e90001aab9d00200d00c1325335333573466"
    "e1d200035573a00201c01a2666ae68cdc79bae357426aae7800cdd71aba135573c00201c01a26004931baa0031"
    "300149894cd4ccd5cd19b8748008d55ce801006806099299a999ab9a3370e90011aab9d00100e00d1333573466"
    "e3cdd71aba135573c0066eb8d5d09aab9e00100e00d100d375400620186ea8008888c94cd4ccd5cd19b8748008"
    "d55ce800806005899191998029bad357420046eb4d5d08009bad357426ae88004d5d10009aab9e00113002498d"
    "d5001900091119299a999ab9a3370e90001aab9d00100a00913003375c6ae84d55cf0008980124c6ea800c888c"
    "8cc00cd5d08009aba1357440026aae78dd50019111112999999aba40011323300735573a0026aae78004dd5000"
    "898029bab001130043758002260066eb40044c008dd700091119191919998029aba100337566ae84008d5d0800"
    "99803bae357426ae88004d5d10009aba200135573c6ea800c88c8c8c94cd4ccd5cd19b874800800801c0185402"
    "054cd4ccd5cd19b874800000801c0184c024c014d5d08008b1aab9e00235573a0026ea80044880084880048488"
    "c00800c448800448cc00488cdc0001000a4001"
);

/// The script hash of the committee candidate validator of the partner chain
/// whose genesis UTXO is `tx_hash#index`.
pub fn validator_hash(tx_hash: &[u8; 32], index: u16) -> Result<[u8; 28], String> {
    script_hash(&COMMITTEE_CANDIDATE_VALIDATOR, &[utxo_data(tx_hash, index)])
}

/// The D-parameter and the permissioned candidates policy ids of the partner
/// chain whose genesis UTXO is `tx_hash#index`.
pub fn policy_ids(tx_hash: &[u8; 32], index: u16) -> Result<([u8; 28], [u8; 28]), String> {
    let utxo = utxo_data(tx_hash, index);
    let oracle_validator = script_hash(&VERSION_ORACLE_VALIDATOR, &[utxo.clone()])?;
    let oracle = bytes_data(&script_hash(
        &VERSION_ORACLE_POLICY,
        &[utxo.clone(), script_address_data(&oracle_validator)],
    )?);
    let policy = |validator: &[u8], policy: &[u8]| {
        let validator = script_hash(validator, &[utxo.clone(), oracle.clone()])?;
        script_hash(
            policy,
            &[
                utxo.clone(),
                oracle.clone(),
                script_address_data(&validator),
            ],
        )
    };
    Ok((
        policy(&D_PARAMETER_VALIDATOR, &D_PARAMETER_POLICY)?,
        policy(
            &PERMISSIONED_CANDIDATES_VALIDATOR,
            &PERMISSIONED_CANDIDATES_POLICY,
        )?,
    ))
}

/// The hash of `script` applied to each of `parameters` in turn, as a Plutus
/// V2 script.
fn script_hash(script: &[u8], parameters: &[Vec<u8>]) -> Result<[u8; 28], String> {
    let mut applied = script.to_vec();
    for parameter in parameters {
        applied = apply_data(&applied, parameter)?;
    }
    let hash = blake2b_simd::Params::new()
        .hash_length(28)
        .to_state()
        .update(&[PLUTUS_V2])
        .update(&applied)
        .finalize();
    hash.as_bytes()
        .try_into()
        .map_err(|_| "blake2b-224 gave no 28 bytes".to_string())
}

/// The language tag a Plutus V2 script's hash covers before the script.
const PLUTUS_V2: u8 = 2;

/// The UTXO as Plutus data, `Constr 0 [Constr 0 [tx_hash], index]`, in the
/// CBOR partner-chains writes a script parameter in: each non-empty list of
/// fields of indefinite length.
fn utxo_data(tx_hash: &[u8; 32], index: u16) -> Vec<u8> {
    const CONSTR_0_FIELDS: [u8; 3] = [0xd8, 0x79, 0x9f];
    const BREAK: u8 = 0xff;
    let mut data = Vec::with_capacity(48);
    data.extend(CONSTR_0_FIELDS);
    data.extend(CONSTR_0_FIELDS);
    data.extend(cbor_head(BYTES, 32));
    data.extend(tx_hash);
    data.push(BREAK);
    data.extend(cbor_head(UNSIGNED, index.into()));
    data.push(BREAK);
    data
}

/// A byte string of at most 64 bytes as Plutus data, which CBOR writes
/// whole.
fn bytes_data(bytes: &[u8]) -> Vec<u8> {
    [cbor_head(BYTES, bytes.len() as u64), bytes.to_vec()].concat()
}

/// An enterprise script address as Plutus data: `Constr 0 [Constr 1
/// [script hash], Constr 1 []]`, a script payment credential and no stake
/// credential.
fn script_address_data(script_hash: &[u8; 28]) -> Vec<u8> {
    const CONSTR_0_FIELDS: [u8; 3] = [0xd8, 0x79, 0x9f];
    const CONSTR_1_FIELDS: [u8; 3] = [0xd8, 0x7a, 0x9f];
    const CONSTR_1_EMPTY: [u8; 3] = [0xd8, 0x7a, 0x80];
    const BREAK: u8 = 0xff;
    [
        &CONSTR_0_FIELDS[..],
        &CONSTR_1_FIELDS,
        &bytes_data(script_hash),
        &[BREAK],
        &CONSTR_1_EMPTY,
        &[BREAK],
    ]
    .concat()
}

const UNSIGNED: u8 = 0;
const BYTES: u8 = 2;

fn cbor_head(major: u8, n: u64) -> Vec<u8> {
    let major = major << 5;
    match n {
        0..=23 => vec![major | n as u8],
        24..=0xff => vec![major | 24, n as u8],
        0x100..=0xffff => [vec![major | 25], (n as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![major | 26], (n as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![major | 27], n.to_be_bytes().to_vec()].concat(),
    }
}

/// The bytes a CBOR byte string holds, which must be all of `cbor`.
fn cbor_bytes(cbor: &[u8]) -> Result<&[u8], String> {
    let (length, start) = match cbor {
        [head @ 0x40..=0x57, ..] => (usize::from(head & 0x1f), 1),
        [0x58, n, ..] => (usize::from(*n), 2),
        [0x59, a, b, ..] => (usize::from(u16::from_be_bytes([*a, *b])), 3),
        _ => return Err("the script is not a CBOR byte string".to_string()),
    };
    if cbor.len() != start + length {
        return Err("the script's CBOR byte string is not the whole script".to_string());
    }
    Ok(&cbor[start..])
}

/// `script`, a CBOR byte string holding a flat-encoded program, applied to the
/// Plutus data `data`: the program `[term (con data data)]` with the script's
/// version, flat-encoded and in a CBOR byte string again.
fn apply_data(script: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let program = cbor_bytes(script)?;
    let mut flat = Flat::new(program);
    for _ in 0..3 {
        flat.copy_word()?;
    }
    flat.put(APPLY, TERM_TAG_BITS);
    flat.copy_term()?;
    flat.skip_filler()?;
    if flat.read != 8 * program.len() {
        return Err("the program goes on after its term".to_string());
    }
    flat.put(CONSTANT, TERM_TAG_BITS);
    flat.put(1, 1);
    flat.put(DATA, TYPE_TAG_BITS);
    flat.put(0, 1);
    flat.put_bytes(data);
    flat.put_filler();
    let mut applied = cbor_head(BYTES, flat.out.len() as u64);
    applied.extend(flat.out);
    Ok(applied)
}

const TERM_TAG_BITS: u32 = 4;
const TYPE_TAG_BITS: u32 = 4;
const BUILTIN_BITS: u32 = 7;
const APPLY: u64 = 3;
const CONSTANT: u64 = 4;
const DATA: u64 = 8;

const UNREADABLE_APPLICATION: &str = "the script holds a type application it cannot read";

/// A constant's type, as its flat list of type tags spells it.
enum Type {
    Integer,
    Bytes,
    Unit,
    Bool,
    List(Box<Type>),
    Pair(Box<Type>, Box<Type>),
}

impl Type {
    fn read(tags: &mut impl Iterator<Item = u64>) -> Result<Type, String> {
        Ok(match tags.next() {
            Some(0) => Type::Integer,
            Some(1 | 2 | 8) => Type::Bytes,
            Some(3) => Type::Unit,
            Some(4) => Type::Bool,
            Some(7) => match tags.next() {
                Some(5) => Type::List(Box::new(Type::read(tags)?)),
                Some(7) => match tags.next() {
                    Some(6) => Type::Pair(Box::new(Type::read(tags)?), Box::new(Type::read(tags)?)),
                    _ => return Err(UNREADABLE_APPLICATION.to_string()),
                },
                _ => return Err(UNREADABLE_APPLICATION.to_string()),
            },
            _ => return Err("the script holds a constant type it cannot read".to_string()),
        })
    }
}

/// A flat-encoded program read bit by bit and copied, shifted, to `out`.
struct Flat<'a> {
    input: &'a [u8],
    read: usize,
    out: Vec<u8>,
    written: usize,
}

impl<'a> Flat<'a> {
    fn new(input: &'a [u8]) -> Self {
        Flat {
            input,
            read: 0,
            out: Vec::with_capacity(input.len() + 64),
            written: 0,
        }
    }

    fn take(&mut self, bits: u32) -> Result<u64, String> {
        let mut value = 0;
        for _ in 0..bits {
            let byte = self
                .input
                .get(self.read / 8)
                .ok_or("the program ends early")?;
            value = value << 1 | u64::from(byte >> (7 - self.read % 8) & 1);
            self.read += 1;
        }
        Ok(value)
    }

    fn put(&mut self, value: u64, bits: u32) {
        for bit in (0..bits).rev() {
            if self.written % 8 == 0 {
                self.out.push(0);
            }
            if value >> bit & 1 == 1 {
                let at = self.written / 8;
                self.out[at] |= 0x80 >> (self.written % 8);
            }
            self.written += 1;
        }
    }

    fn copy(&mut self, bits: u32) -> Result<u64, String> {
        let value = self.take(bits)?;
        self.put(value, bits);
        Ok(value)
    }

    /// A natural: 7 bits a byte, each byte's top bit saying another follows.
    fn copy_word(&mut self) -> Result<(), String> {
        while self.copy(8)? & 0x80 != 0 {}
        Ok(())
    }

    /// Zero bits and a one up to a byte boundary.
    fn skip_filler(&mut self) -> Result<(), String> {
        while self.take(1)? == 0 {}
        if self.read % 8 != 0 {
            return Err("the program's filler ends off a byte boundary".to_string());
        }
        Ok(())
    }

    fn put_filler(&mut self) {
        while self.written % 8 != 7 {
            self.put(0, 1);
        }
        self.put(1, 1);
    }

    /// A byte string: aligned by a filler, which moves with where the string
    /// starts, then chunks of at most 255 bytes, each after its length, and
    /// an empty chunk.
    fn copy_bytes(&mut self) -> Result<(), String> {
        self.skip_filler()?;
        self.put_filler();
        loop {
            let length = self.copy(8)?;
            if length == 0 {
                return Ok(());
            }
            for _ in 0..length {
                self.copy(8)?;
            }
        }
    }

    fn put_bytes(&mut self, bytes: &[u8]) {
        self.put_filler();
        for chunk in bytes.chunks(255) {
            self.put(chunk.len() as u64, 8);
            for byte in chunk {
                self.put(u64::from(*byte), 8);
            }
        }
        self.put(0, 8);
    }

    fn copy_value(&mut self, of: &Type) -> Result<(), String> {
        match of {
            Type::Integer => self.copy_word(),
            Type::Bytes => self.copy_bytes(),
            Type::Unit => Ok(()),
            Type::Bool => self.copy(1).map(drop),
            Type::List(item) => {
                while self.copy(1)? == 1 {
                    self.copy_value(item)?;
                }
                Ok(())
            }
            Type::Pair(first, second) => {
                self.copy_value(first)?;
                self.copy_value(second)
            }
        }
    }

    /// One term with its subterms: a variable, delay, lambda, application,
    /// constant, force, error or builtin. The scripts are UPLC 1.0, which has
    /// no constr or case.
    fn copy_term(&mut self) -> Result<(), String> {
        let mut pending = 1u32;
        while pending > 0 {
            pending -= 1;
            match self.copy(TERM_TAG_BITS)? {
                0 => self.copy_word()?,
                1 | 2 | 5 => pending += 1,
                APPLY => pending += 2,
                CONSTANT => {
                    let mut tags = Vec::new();
                    while self.copy(1)? == 1 {
                        tags.push(self.copy(TYPE_TAG_BITS)?);
                    }
                    let mut tags = tags.into_iter();
                    let of = Type::read(&mut tags)?;
                    if tags.next().is_some() {
                        return Err("a constant's type list goes on after its type".to_string());
                    }
                    self.copy_value(&of)?;
                }
                6 => {}
                7 => {
                    self.copy(BUILTIN_BITS)?;
                }
                tag => return Err(format!("the program holds term tag {tag}, not UPLC 1.0")),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bech32_payload(text: &str) -> Vec<u8> {
        use bech32::FromBase32;
        let (_, data) = bech32::decode(text).expect("bech32");
        Vec::<u8>::from_base32(&data).expect("whole bytes")
    }

    fn utxo(text: &str) -> ([u8; 32], u16) {
        let (tx, index) = text.split_once('#').expect("tx#index");
        let tx = sp_core::bytes::from_hex(tx).expect("hex");
        (
            tx.try_into().expect("32 bytes"),
            index.parse().expect("an index"),
        )
    }

    /// Preprod was set up with partner-chains v1.8.0, and its nodes read
    /// registrations at the address its genesis stores: the validator of its
    /// genesis UTXO, on the test network (header 0x70).
    #[test]
    fn the_validator_of_preprods_genesis_utxo_is_at_the_address_preprods_genesis_stores() {
        let preprod = crate::chain_spec_preprod::genesis_patch();
        let (tx, index) = utxo(preprod["sidechain"]["genesisUtxo"].as_str().unwrap());
        let stored = preprod["sessionCommitteeManagement"]["mainChainScripts"]
            ["committee_candidate_address"]
            .as_str()
            .unwrap();
        let text = String::from_utf8(sp_core::bytes::from_hex(stored).unwrap()).unwrap();
        let hash = validator_hash(&tx, index).unwrap();
        assert_eq!(
            hash,
            hex!("fed2f2fdc87b0a9d6e91220cb2788107793413b094e172a414b0a05c")
        );
        assert_eq!(bech32_payload(&text), [&[0x70], &hash[..]].concat());
    }

    #[test]
    fn each_genesis_utxo_parameterises_a_validator_of_its_own() {
        let (tx, index) =
            utxo("13313ea0119e0c4330f64f1809159064a371a1bbf2050b1fe13d5492280dca50#0");
        let mut other_tx = tx;
        other_tx[31] ^= 1;
        let hashes = [
            validator_hash(&tx, index).unwrap(),
            validator_hash(&tx, 1).unwrap(),
            validator_hash(&tx, 300).unwrap(),
            validator_hash(&tx, 32767).unwrap(),
            validator_hash(&other_tx, index).unwrap(),
        ];
        let distinct: std::collections::BTreeSet<_> = hashes.iter().collect();
        assert_eq!(distinct.len(), hashes.len());
    }

    /// The vectors partner-chains v1.8.0's `get-scripts` gives: preprod's
    /// genesis UTXO derives the policy ids preprod's genesis stores, and the
    /// launch fixture's the ones its manifest names.
    #[test]
    fn the_policies_of_a_genesis_utxo_are_the_ones_partner_chains_derives() {
        let preprod = crate::chain_spec_preprod::genesis_patch();
        let scripts = &preprod["sessionCommitteeManagement"]["mainChainScripts"];
        let stored = |name: &str| sp_core::bytes::from_hex(scripts[name].as_str().unwrap());
        let (tx, index) = utxo(preprod["sidechain"]["genesisUtxo"].as_str().unwrap());
        let (d_parameter, permissioned_candidates) = policy_ids(&tx, index).unwrap();
        assert_eq!(
            d_parameter,
            hex!("38dddaf5198b927b19dac9b28226ab29eddad176d5d81c7748bc2c31")
        );
        assert_eq!(
            permissioned_candidates,
            hex!("ef2890d1e98247819abcf2df6e891824ed950a4216d36c71ee6f9974")
        );
        assert_eq!(stored("d_parameter_policy_id").unwrap(), d_parameter);
        assert_eq!(
            stored("permissioned_candidates_policy_id").unwrap(),
            permissioned_candidates
        );
        let (tx, index) =
            utxo("09b6fee196c91cd2a78183f837b83f8410183edcdf1edca6e80ff7571dd7a75d#0");
        assert_eq!(
            policy_ids(&tx, index).unwrap(),
            (
                hex!("bca168784c7086baa491ff876a1e9d6ee2b8a418a841dc0d445a674e"),
                hex!("8d5698c66e509f7758befcca95b5bc1632daf4b864d5fdd049dc40b2")
            )
        );
    }

    #[test]
    fn each_genesis_utxo_parameterises_policies_of_its_own() {
        let (tx, index) =
            utxo("13313ea0119e0c4330f64f1809159064a371a1bbf2050b1fe13d5492280dca50#0");
        let mut other_tx = tx;
        other_tx[31] ^= 1;
        let derived = [
            policy_ids(&tx, index).unwrap(),
            policy_ids(&tx, 1).unwrap(),
            policy_ids(&tx, 32767).unwrap(),
            policy_ids(&other_tx, index).unwrap(),
        ];
        let distinct: std::collections::BTreeSet<_> =
            derived.iter().flat_map(|(d, p)| [d, p]).collect();
        assert_eq!(distinct.len(), 2 * derived.len());
    }

    /// The scripts are the ones the launch preflight vendors from
    /// partner-chains-smart-contracts v8.1.0 and derives rule 9's values with.
    #[test]
    fn the_scripts_are_the_ones_the_launch_preflight_vendors() {
        let table: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tools/launch-preflight/partner_chains_scripts.json"
        ))
        .unwrap();
        let vendored = |name: &str| {
            sp_core::bytes::from_hex(table["scripts"][name].as_str().unwrap()).unwrap()
        };
        let applied: [(&str, &[u8]); 7] = [
            (
                "committee_candidate_validator",
                &COMMITTEE_CANDIDATE_VALIDATOR,
            ),
            ("version_oracle_validator", &VERSION_ORACLE_VALIDATOR),
            ("version_oracle_policy", &VERSION_ORACLE_POLICY),
            ("d_parameter_validator", &D_PARAMETER_VALIDATOR),
            ("d_parameter_policy", &D_PARAMETER_POLICY),
            (
                "permissioned_candidates_validator",
                &PERMISSIONED_CANDIDATES_VALIDATOR,
            ),
            (
                "permissioned_candidates_policy",
                &PERMISSIONED_CANDIDATES_POLICY,
            ),
        ];
        assert_eq!(table["scripts"].as_object().unwrap().len(), applied.len());
        for (name, script) in applied {
            assert_eq!(vendored(name), script, "{name}");
        }
    }

    #[test]
    fn a_script_address_is_the_plutus_data_partner_chains_writes() {
        assert_eq!(
            sp_core::bytes::to_hex(&script_address_data(&[0; 28]), false),
            format!("0xd8799fd87a9f581c{}ffd87a80ff", "00".repeat(28))
        );
    }

    #[test]
    fn the_utxo_is_the_plutus_data_partner_chains_writes() {
        let data = utxo_data(&[0xab; 32], 300);
        assert_eq!(
            sp_core::bytes::to_hex(&data, false),
            format!("0xd8799fd8799f5820{}ff19012cff", "ab".repeat(32))
        );
        assert_eq!(utxo_data(&[0xab; 32], 0)[41..], [0x00, 0xff]);
        assert_eq!(utxo_data(&[0xab; 32], 24)[41..], [0x18, 0x18, 0xff]);
    }

    #[test]
    fn a_script_that_is_not_one_whole_cbor_byte_string_is_refused() {
        let mut longer = COMMITTEE_CANDIDATE_VALIDATOR.to_vec();
        longer.push(0);
        let mut truncated = COMMITTEE_CANDIDATE_VALIDATOR.to_vec();
        truncated[1] += 1;
        truncated.push(0);
        for script in [
            &longer[..],
            &truncated[..],
            &COMMITTEE_CANDIDATE_VALIDATOR[1..],
        ] {
            assert!(apply_data(script, &[0]).is_err());
        }
    }
}
