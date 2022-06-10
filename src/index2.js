const express = require('express');
var bodyParser = require('body-parser');
const lithium_sso = require("./lithium_sso");

const app = express();

app.set('trust proxy', true);

app.use(bodyParser.json());

app.get("/", (req, res) => {
    try{
    const sso_key = "d41d8cd98f00b204e9800998ecf8427e",
    HTTP_USER_AGENT = req.headers['user-agent'],
    HTTP_REFERER = req.headers.referer,
    REMOTE_ADDR = req.ip,
    SERVER_ID = "";

    console.log('1. HTTP_USER_AGENT = ' + HTTP_USER_AGENT);
    console.log('2. HTTP_REFERER = ' + HTTP_REFERER);
    console.log('3. REMOTE_ADDR = ' + REMOTE_ADDR);
    const lithium = new lithium_sso("example", ".example.com", sso_key, SERVER_ID, HTTP_USER_AGENT,  HTTP_REFERER, REMOTE_ADDR);

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
    };
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