import axios, { AxiosHeaders, AxiosInstance, AxiosResponse } from 'axios';
import qs from 'querystring';
import CryptoJS from 'crypto-js';
import iconv from 'iconv-lite';
import FormData from 'form-data';

/** godomall 1번째 타입 */
type GODO = "login_ps.php" | "godomall" | "A";
/** 일반 hosting B 타입 */
type SHOP_B = "shop/member.html" | "B" | "shop/member.html_POPUP" | "B_POPUP";
/** godomall 2번째 타입 */
type GODO_2 = "login_ok.php" | "C" | "godomall2";
/** godomall 3번째 타입. google recaptcha 과정을 거친 키를 넘겨줘야 함. 굉장히 까다로움 */
type GODO_GRECAPTCHA = "login_ok.php_GRECAPTCHA"|"C_GRECAPTCHA"|"godomall_GRECAPTCHA";
/** cafe24. 암호화X, 평문 */
type CAFE24 = "cafe24"|"D";
/** godomall 4번째 타입 */
type GODO_ENCRYPT = "login_ps.php_ENCRYPT"|"godomall_ENCRYPT"|"A_ENCRYPT";
/** _(미완)_ godomall_ENCRYPT 타입이되 metadata인 헤더 검증과정이 추가됨.. (2024-04-05 리뉴얼 추가) */
type GODO_ENCRYPT2 = "login_ps.php_ENCRYPT2"|"godomall_ENCRYPT2"|"A_ENCRYPT2";
/** cafe24 encrypt (renewal) */
type CAFE24_ENCRYPT = "cafe24_renewal"|"D_renewal";
/** nechingu @link http://nechingu.com/ */    
type NECHINGU = "nechingu";
/** sixshop @link https://www.sixshop.com/ */
type SIXSHOP = "sixshop";
/** imweb @link https://imweb.me/ */
type IMWEB = "imweb";

type ALL_OPEN_LOGIN_TYPE = GODO | SHOP_B | GODO_2 | GODO_GRECAPTCHA | CAFE24 | GODO_ENCRYPT | GODO_ENCRYPT2 | CAFE24_ENCRYPT | NECHINGU | SIXSHOP | IMWEB;

interface doLoginOptions {
    chkLoginExpression?: (res: AxiosResponse) => boolean;
    chkLoginExpressionAfterPostPopup?: (res: AxiosResponse) => boolean;
    additionalHeaders?: Partial<AxiosHeaders>;
    memberform_sslid?: string;
    responseType?: "document" | "text";
    loginFormData?: { [key: string]: string; };
    info?: { [key: string]: any; };
}


function getValue(content:string, rule:RegExp|string, err:boolean = false) {
    var value = '';
    var regex = new RegExp(rule, "img"); // 정규식

    var match = regex.exec(content);
    if (match) {
        value = match[1].trim();
    } else {
        if (err)
            throw new Error(`utils getValue error occurred, rule : ${rule}`);
    }

    return value;
}

function parseCookie(cookieStr:string) {
    let cookies = {};

    cookieStr
        .split(";")
        .filter((v) => !!v)
        .map((v) => v.trim().split('='))
        .map((v) => cookies[v[0]] = v[1]);

    return cookies;
}

function setCookieStr(cookiesJSON:Object) {
    let result = '';
    
    for (let key in cookiesJSON) {
        if (result !== "")
            result += '; ';

        result += `${key}=${cookiesJSON[key]}`;
    }

    return result;
}


function setNewCookie(cookieStr:string, newCookieStr:string, options={override: false, useDeleted: true, useOnlyData: true}) {
    let orgCookies = parseCookie(cookieStr);
    let result = JSON.parse(JSON.stringify(orgCookies));
    let newCookies = parseCookie(newCookieStr);

    for (let key in newCookies) {
        if (newCookies[key] === undefined)
            continue;

        if (newCookies[key] == "deleted") {
            if (options.useDeleted)
                delete orgCookies[key];

            continue;
        }

        if (options.useOnlyData && /^expires|path|domain|max-age|secure$/i.test(key))
            continue;

        if (result[key] == undefined) {
            result[key] = newCookies[key];
        } else {
            if (options.override)
                result[key] = newCookies[key];
            else
                continue;
        }
    }

    return setCookieStr(result);
}

/**
 * **로그인**
 * 
 * > 반드시 첫번째 파라미터로 this (class) 를 넘겨주어야 하며, class의 선언 내에 PR_COOKIE, defaultHeaders가 정의되어있어야 함 \
 * > 이때,
 * > - PR_COOKIE : 진행중 계속 들고 갈 쿠키를 담아놓을 변수
 * > - defaultHeaders: 기본헤더값 
 */
export async function doLogin(
    siteDriver:any, 
    loginType: ALL_OPEN_LOGIN_TYPE, 
    host: string, 
    id: string, 
    pw: string, 
    options:doLoginOptions = {
        chkLoginExpression: undefined,
        chkLoginExpressionAfterPostPopup: undefined,
        additionalHeaders: {},
        memberform_sslid: undefined,
        responseType: "document",
        loginFormData: {},
        info: {}
    }
) {
    let success = false;

    try {
        // default settings
        let $axios:AxiosInstance = axios;;

        let _ = () => {
            $axios = axios.create({
                baseURL: host,
                timeout: 60 * 1000,
                headers: {
                    ...siteDriver.defaultHeaders,
                    'Cookie': siteDriver.PR_COOKIE
                }
            });
        }
        _();

        $axios.interceptors.response.use((res) => {
            for (let i in res.headers['set-cookie'])
                siteDriver.PR_COOKIE = setNewCookie(siteDriver.PR_COOKIE, res.headers['set-cookie'][i]);

            _();

            return res;
        });

        if (loginType === "login_ps.php" || loginType === "godomall" || loginType === "A") {
            await $axios.get(`/member/login.php`);

            const reqData = qs.stringify({
                'mode': 'login',
                'returnUrl': encodeURIComponent(host),
                'loginId': id,
                'loginPwd': pw,
                'saveId': 'y',
            });
            let res = await $axios.post(`/member/login_ps.php`, reqData);

            success = (res.status >= 200 && res.status < 300) && (!options.chkLoginExpression || options.chkLoginExpression(res));
        } else if (loginType === "login_ps.php_ENCRYPT" || loginType === "godomall_ENCRYPT" || loginType === "A_ENCRYPT" || loginType === "login_ps.php_ENCRYPT2" || loginType === "godomall_ENCRYPT2" || loginType === "A_ENCRYPT2") {
            let secretKey = '', csrf_token = '';

            var Encryption = {
                get encryptMethod() {
                    return 'AES-256-CBC';
                },

                get encryptMethodLength() {
                    var encryptMethod = this.encryptMethod;
                    var aesNumber = encryptMethod.match(/\d+/)[0];
                    return parseInt(aesNumber);
                },
                
                encrypt : function (string, key) {
                    var iv = CryptoJS.lib.WordArray.random(16);
                    var salt = CryptoJS.lib.WordArray.random(256);
                    var iterations = 999;
                    var encryptMethodLength = (this.encryptMethodLength/4);
                    var hashKey = CryptoJS.PBKDF2(key, salt, {'hasher': CryptoJS.algo.SHA512, 'keySize': (encryptMethodLength/8), 'iterations': iterations});
                    var encrypted = CryptoJS.AES.encrypt(string, hashKey, {'mode': CryptoJS.mode.CBC, 'iv': iv});
                    var encryptedString = CryptoJS.enc.Base64.stringify(encrypted.ciphertext);

                    var output = {
                        'ciphertext': encryptedString,
                        'iv': CryptoJS.enc.Hex.stringify(iv),
                        'salt': CryptoJS.enc.Hex.stringify(salt),
                        'iterations': iterations
                    };

                    return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(JSON.stringify(output)));
                },

                /**
                 * form serialize 값 변경
                 *
                 * @param values 폼명
                 * @param k 변경할 inputName
                 * @param v 변경할 inputValue
                 */
                changeSerialize: function(values, k, v) {
                    var found = false;
                    for (let i = 0; i < values.length && !found; i++) {
                        if (values[i].name == k) {
                            values[i].value = v;
                            found = true;
                        }
                    }

                    if (!found) {
                        values.push({name: k,value: v});
                    }
                    return values;
                }
            }

            let res = await $axios.get("/member/login.php");
            secretKey = getValue(res.data, /<input type=['"]hidden['"]\s*id=['"]secretKey['"].+value=['"]([^'"]+)/);
            if (!!secretKey && secretKey.length > 10) {
                csrf_token = getValue(res.data, /<meta name=['"]csrf-token['"]\s*content=['"]([^'"]+)/);
                if (!!csrf_token && csrf_token.length > 10)
                    success = true;
                else
                    throw new Error("can't find csrf_token");
            }

            let data = qs.stringify({
                'mode': 'login',
                'returnUrl': `${encodeURIComponent(host)}`,
                'secretKey': secretKey,
                'encryptFl': 'Y',
                'loginId': Encryption.encrypt(id, secretKey),
                'loginPwd': Encryption.encrypt(pw, secretKey),
                'saveId': 'y',
            });
            res = await $axios.post("/member/login_ps.php", data, {
                headers: {
                    'Accept': '*/*',
                    'Accept-Encoding': 'gzip, deflate, br, zstd',
                    'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Content-Length': data.length,
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Cookie': siteDriver.PR_COOKIE,
                    'Origin': `${host}`,
                    'Referer': `${host}/member/login.php`,
                    'Sec-Ch-Ua': '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-origin',
                    'User-Agent': siteDriver['User-Agent'] || siteDriver['user-agent'],
                    'X-CSRF-Token': csrf_token,
                    'X-Requested-With': 'XMLHttpRequest',
                },
                maxRedirects: 0
            });

            success = (res.status >= 200 && res.status < 300) && (!options.chkLoginExpression || options.chkLoginExpression(res));
        } else if (loginType === "shop/member.html" || loginType === "B" || loginType === "shop/member.html_POPUP" || loginType === "B_POPUP") {
            await $axios.get(`/shop/member.html?type=login`);

            let data = qs.stringify({
                'type': 'login',
                'sslid': !!options.memberform_sslid ? options.memberform_sslid : getValue(host, /(?:https?:\/*|www\.)([^\.]+)/),
                'sslip': host.replace(/(?:https?:\/*|\/)/g, ''),
                'returnurl': host,
                'id': id,
                'passwd': pw
            });

            let res = await $axios.post(`/shop/member.html`, data);
            
            success = (res.status >= 200 && res.status < 300) && (!options.chkLoginExpression || options.chkLoginExpression(res));

            if (success && (loginType === "B_POPUP" || loginType === "shop/member.html_POPUP")) {
                success = false;

                res = await $axios.get(`/shop/mypage_mypassword.action.html?action_type=popup&reurl=${encodeURIComponent(host)}%2Findex.html`);
                success = !options.chkLoginExpressionAfterPostPopup || options.chkLoginExpressionAfterPostPopup(res);
            }
        } else if (loginType === "godomall2" || loginType === "login_ok.php" || loginType === "C") {
            await $axios.get(`/shop/member/login.php`);

            if (!!options.loginFormData && JSON.stringify(options.loginFormData) !== '{}') {
                let data = qs.stringify(options.loginFormData);
                let res = await $axios.post(`/shop/member/login_ok.php`, data);
                success = (res.status >= 200 && res.status < 300) && (!options.chkLoginExpression || options.chkLoginExpression(res));
            } else {
                throw new Error('loginFormData is empty');
            }
        } else if (loginType === "cafe24" || loginType === "D" || loginType === "cafe24_renewal" || loginType === "D_renewal") {
            let sLoginKey = '';
            let member_form_id = '';
            let aLogData = '';

            let res = await $axios.get(`/member/login.html`);
            // aLogData
            try {
                aLogData = JSON.parse(getValue(res.data, /var\s+aLogData\s*=\s*(\{[^;]+\});/));
            } catch (error) {
                throw new Error(`login failed`);
            }

            // member_form_id 설정
            member_form_id = getValue(res.data, /(member_form_[0-9]+)/);

            res = await $axios.post(`/exec/front/Member/loginKey`, '');
            if (res.data.sIsPass === "T")
                sLoginKey = res.data.sKey;
            else
                throw new Error(`login failed`);

            await $axios.post(`/exec/front/Member/CheckCaptcha/`, undefined);

            if (loginType === "cafe24_renewal" || loginType === "D_renewal") {
                let auth_str = {
                    [`${member_form_id}::member_id`]:id,
                    [`${member_form_id}::member_passwd`]:pw,
                    [`${member_form_id}::check_save_id[]`]:"",
                    [`${member_form_id}::member_check_save_id[]`]:"",
                    [`${member_form_id}::returnUrl`]:encodeURIComponent(host),
                    [`${member_form_id}::forbidIpUrl`]:"%2Findex.html",
                    [`${member_form_id}::certificationUrl`]:"%2Fintro%2Fadult_certification.html",
                    [`${member_form_id}::sIsSnsCheckid`]:"",
                    [`${member_form_id}::sProvider`]:"",
                    [`${member_form_id}::check_save_id`]:"",
                    [`${member_form_id}::use_login_keeping`]:"",
                    [`${member_form_id}::sLoginKey`]:sLoginKey,
                    [`${member_form_id}::use_login_keeping_no`]:"",
                    [`${member_form_id}::is_use_login_keeping_ip`]:""
                };

                let data = qs.stringify({
                    auth_mode: "encrypt",
                    auth_callbackName: "AuthSSL.encryptSubmit_Complete",
                    auth_string: JSON.stringify(auth_str),
                    dummy: new Date().getTime()
                });
                let url = `https://login2.cafe24ssl.com/crypt/AuthSSLManagerV2.php?` + data;
                let authKey;
                res = await $axios.get(url, {
                    headers: {
                        'Accept': '*/*',
                        'Accept-Encoding': 'gzip, deflate, br',
                        'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
                        'Connection': 'keep-alive',
                        'Host': 'login2.cafe24ssl.com',
                        'Referer': host,
                        'sec-ch-ua': '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
                        'sec-ch-ua-mobile': '?0',
                        'sec-ch-ua-platform': '"Windows"',
                        'Sec-Fetch-Dest': 'script',
                        'Sec-Fetch-Mode': 'no-cors',
                        'Sec-Fetch-Site': 'cross-site',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'
                    }
                });

                authKey = getValue(res.data, /AuthSSL\.encryptSubmit_Complete\(['"]([^'"]+)/);

                if (!!authKey) {
                    let formData = new FormData();
                    let formboundary = 'WebKitFormBoundaryu2LnIkHGpo88tcgP';
                    formData.setBoundary(formboundary);
                    formData.append('returnUrl', '');
                    formData.append('forbidIpUrl', '');
                    formData.append('certificationUrl', '');
                    formData.append('sIsSnsCheckid', '');
                    formData.append('sProvider', '');
                    formData.append('member_id', '');
                    formData.append('member_passwd', '');
                    formData.append('sLoginKey', '');
                    formData.append('encrypted_str', authKey);
                    
                    formData.getLength(async (err, length) => {
                        let form_len = length || 0;
                        res = await $axios.post("/exec/front/Member/login/", formData, {
                            headers: {
                                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                                'accept-encoding': 'gzip, deflate, br',
                                'accept-language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
                                'cache-control': 'max-age=0',
                                'content-length': `${form_len}`,
                                'content-type': `multipart/form-data; boundary=----${formboundary}`,
                                'cookie': siteDriver.PR_COOKIE,
                                'origin': host,
                                'referer': `${host}/member/login.html`,
                                'sec-ch-ua': '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
                                'sec-ch-ua-mobile': '?0',
                                'sec-ch-ua-platform': '"Windows"',
                                'sec-fetch-dest': 'document',
                                'sec-fetch-mode': 'navigate',
                                'sec-fetch-site': 'same-origin',
                                'sec-fetch-user': '?1',
                                'upgrade-insecure-requests': '1',
                                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'
                            }
                        });
                        
                        success = res.status >= 200 && res.status < 300 ? true : false;
                    });
                }
            } else {
                let data = qs.stringify({
                    member_id: id,
                    member_passwd: pw
                });

                res = await $axios.post(`/exec/front/Member/login/`, data);
                success = (res.status >= 200 && res.status < 300) && (!options.chkLoginExpression || options.chkLoginExpression(res));
            }
        } else if (loginType === "login_ok.php_GRECAPTCHA" || loginType === "C_GRECAPTCHA" || loginType === "godomall_GRECAPTCHA") {
            
        } else if (loginType === "nechingu") {
            await $axios.get('/login.asp');

            await $axios.get(`/common/ajax/exec_getTopmenuBox.asp?rnd=${Math.random()}`, {
                headers: {
                    ...siteDriver.headers,
                    ...options.additionalHeaders,
                    'Referer': `${host}/login.asp`
                }
            });

            await $axios.get(`/dummy.asp`, {
                headers: {
                    ...siteDriver.headers,
                    ...options.additionalHeaders,
                    'Referer': `${host}/login.asp`
                }
            });

            let data = qs.stringify({
                redirect: "",
                id: id,
                pass: pw,
                x: 0,
                y: 0
            });

            let res = await $axios.post(`/loginOk.asp`, data, {
                headers: {
                    ...siteDriver.headers,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Encoding': 'gzip, deflate',
                    'Accept-Language': 'ko-KR,ko;q=0.9',
                    'Cache-Control': 'max-age=0',
                    'Connection': 'keep-alive',
                    'Content-Length': data.length,
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Cookie': siteDriver.PR_COOKIE, 
                    'Host': host.replace(/https?:\/\//, ''),
                    'Origin': `${host}`,
                    'Referer': `${host}/login.asp`,
                    'Upgrade-Insecure-Requests': '1',
                }
            });

            res = await $axios.get(`/main`, {
                headers: {
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Encoding': 'gzip, deflate',
                    'Accept-Language': 'ko-KR,ko;q=0.9',
                    'Connection': 'keep-alive',
                    'Cookie': siteDriver.PR_COOKIE,
                    'Host': host.replace(/^https?:\/\//, ''),
                    'Referer': `${host}/loginOk.asp`,
                    'Upgrade-Insecure-Requests': '1',
                    'User-Agent': siteDriver.defaultHeaders['User-Agent'] || siteDriver.defaultHeaders['user-agent']
                }
            });

            success = (res.status >= 200 && res.status < 300) && (!options.chkLoginExpression || options.chkLoginExpression(res));
        } else if (loginType === "sixshop") {
            await $axios.get('/login', {
                headers: {
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Encoding': 'gzip, deflate, br, zstd',
                    'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Cache-Control': 'max-age=0',
                    'Sec-Ch-Ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
                }
            });

            if (options.info === undefined || options.info.site_no === undefined || options.info.site_key === undefined)
                throw new Error('[options.info] site_no, site_key is required');

            let data = qs.stringify({
                siteLink: getValue(host, /https?:\/\/(?:www\.)?([^\.]+)\./),
                pageLink: "login",
                displayType: "display",
                siteNo: options.info.site_no,
                memberNo: options.info.site_no,
                siteKey: options.info.site_key,
                pageNo: 0,
                shopCustomerNo: 0
            });

            let res = await $axios.post(`/product/getSiteDesignProductAndDefaultData`, data, {
                headers: {
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Encoding': 'gzip, deflate, br, zstd',
                    'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Content-Length': data.length,
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Cookie': siteDriver.PR_COOKIE,
                    'Memberno': options.info.site_no,
                    'Origin': host,
                    'Referer': `${host}/login`,
                    'Sec-Ch-Ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-origin',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            if (res.data.RESULT === "OK") {
                data = qs.stringify({
                    buyNowCartNo: 0,
                    customerEmail: Buffer.from(id).toString("base64"),
                    customerPassword: Buffer.from(pw).toString("base64"),
                    kakaoConnect: "N",
                    kakaoId: "",
                    kakaoReturnUrl: "/",
                    memberNo: options.info.site_no,
                    recaptchaVerified: 0,
                    signupType: "both"
                });

                res = await $axios.post(`/_shop/customer/customerLogin`, data, {
                    headers: {
                        'Accept': 'application/json, text/javascript, */*; q=0.01',
                        'Accept-Encoding': 'gzip, deflate, br, zstd',
                        'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
                        'Content-Length': data.length,
                        'Content-Type': 'application/json; charset=UTF-8',
                        'Cookie': siteDriver.PR_COOKIE,
                        'Member-Id': options.info.site_no,
                        'Memberno': options.info.site_no,
                        'Origin': host,
                        'Referer': `${host}/login`,
                        'Sec-Ch-Ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
                        'Sec-Ch-Ua-Mobile': '?0',
                        'Sec-Ch-Ua-Platform': '"Windows"',
                        'Sec-Fetch-Dest': 'empty',
                        'Sec-Fetch-Mode': 'cors',
                        'Sec-Fetch-Site': 'same-origin',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    maxRedirects: 0
                });

                success = (res.status >= 200 && res.status < 300) && (!options.chkLoginExpression || options.chkLoginExpression(res));
            }
        } else if (loginType === "imweb") {
            await $axios.get('/');
            
            let data = qs.stringify({
                back_url: "Lw%3D%3D",
                type: "null",
                used_login_btn: "Y"
            });
            $axios.post(`/dialog/login.cm`, data);
            
            data = qs.stringify({
                back_url: "Lw%3D%3D",
                back_url_auth: "",
                used_login_btn: "Y",
                uid: id,
                passwd: pw
            });
            let res = await $axios.post(`/backpg/login.cm`, data);

            success = (res.status >= 200 && res.status < 300) && (!options.chkLoginExpression || options.chkLoginExpression(res));
        }
    } catch (error) {
        return false;
    }

    return success;
}