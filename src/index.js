const express = require('express');
var bodyParser = require('body-parser');
const lithium_sso = require("./lithium_sso");

const app = express();

app.set('trust proxy', true);

app.use(bodyParser.json());

app.get("/", (req, res) => {
    try{
    const sso_key = "9DEA5AF94ADCE2BFDE03C3A267555185F7E59FFEAD2B334E0FF1F5193DAF63F4",
    HTTP_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36",
    HTTP_REFERER = " ";
    REMOTE_ADDR = "127.0.0.1",
    SERVER_ID = "127.0.0.1",
    client_id = "nwqwi37788.stage",
    client_domain = ".alphauniverse.com",

    uniqueId = "94f992c8bdaa54b97e97efaff88cd9af:U8bMVff++DxaLLJvqxCa*++uFvoDluSVQBSDMHmd*j2S4dOjwDtr0hiOp7P4tanF",
    login = "mari",
    email = "20200409foo1831@foo.com",
    settings = {
        "profile.name_first" : "Marie",
        "profile.name_last" : "Curie",
      };

    const lithium = new lithium_sso(client_id, client_domain, sso_key, SERVER_ID, HTTP_USER_AGENT, HTTP_REFERER, REMOTE_ADDR);
/*
    // unique id
    let uniqueId = "167865";
    // display name
    let login = "janmon04";
    // email
    let email = "jane.monet@mycompany.com";
    // settings
    let settings = {
        "profile.name_first" : "Jane",
        "profile.name_last" : "Monet",
        "profile.im_id_aim" : "janem04"
    };*/
    //lithium.init_smr(sso_key);
    lithium.get_auth_token(uniqueId, login, email, settings).then(liToken => {
        res.status(200).json({ sso_token: liToken });
    });
}
catch (err) {
    res.status(500).json({ error: err.message });
}
});

app.listen(3000, () => {
    console.log("Server started at port 3000")
});