
    /*
     *
     * STEP 1: Fetch the auth code by having the user log in:
     * 
     */

    function fetchAuthCode() {

        if (!validateInputs(['auth_url', 'authcode_clientid'])) { return; }

        // Clear old auth code and access/refresh tokens
        setInput('authcode', '');
        setInput('accesstoken', '');
        setInput('refreshtoken', '');

        localStorage.setItem('state', generateState());

        // ... and save all our inputs to local storage:
        saveFields();

        // Construct the OAuth 2.0 URL to authenticate:
        var url=getInput('auth_url');
        url = url+(url.indexOf('?')>=0 ? '&' : '?') +
            'response_type=code' +
            '&client_id=' + encodeURIComponent(getInput('authcode_clientid')) +
            '&redirect_uri=' + encodeURIComponent(document.location.origin) +
            '&scope=' + encodeURIComponent(getInput('scope')) +
            '&state=' + encodeURIComponent(localStorage.getItem('state')) +
            '&access_type='+(getInput('access_type_offline') ? 'offline' : 'online')+
            '&prompt='+[getInput('prompt_consent') ? 'consent' : false,
                        getInput('prompt_select_account') ? 'select_account' : false].filter(Boolean).join(' ')

        // .. and open it:
        window.open(url, '_self');
    }

    /*
     *
     * STEP 2: The auth code that comes back from the auth server:
     * 
     */

    function receiveAuthCode(queryStringParams) {
        if (queryStringParams.get('state')!=localStorage.getItem('state')) {
            showDialog('The returned state:\n'+
                queryStringParams.get('state')+
                '\n... is not the one we expected:\n'+
                localStorage.getItem('state'));
        } else {
            setInput('authcode', queryStringParams.get('code'));
            document.querySelector('.authcode-arrow').style.display='block';

            if (queryStringParams.get('scope')) {
                setInput('scope', queryStringParams.get('scope'));
            }
        }
    }

    /*
     *
     * STEP 3 (a): Fetch the access token (auth_code flow)
     * 
     */

    function fetchAccessToken() {
        saveFields();

        if (!validateInputs(['token_url', 'authcode_clientid', 'clientsecret', 'authcode'])) { return; }

        const postData =
             'client_id='+encodeURIComponent(getInput('authcode_clientid'))+
            '&client_secret='+encodeURIComponent(getInput('clientsecret'))+
            '&code='+encodeURIComponent(getInput('authcode'))+
            '&grant_type=authorization_code'+
            '&redirect_uri='+encodeURIComponent(document.location.origin)

        var postUrl=getInput('token_url');
        var proxyData='';
        if (document.querySelector('input[type="checkbox"]#proxy').checked) {
            postUrl='/proxy';
            proxyData='&proxy_target='+encodeURIComponent(getInput('token_url'));
            incrementRequestCount();
        }

        var xhr = new XMLHttpRequest();
        xhr.open('POST', postUrl);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

        xhr.onload = function() {
            var blob={};
            try {
                blob=JSON.parse(xhr.response);
            } catch {
                console.log('Could not parse response as JSON.');
            }

            var reqElement=document.querySelector('#fetchtoken ~ .http-request');
            reqElement.innerText='$ curl \\\n'+
                '   --request POST "'+getInput('token_url')+'" \\\n'+
                '   --header "Content-Type: application/x-www-form-urlencoded" \\\n'+
                '   --data "'+postData.split("&").join('" \\\n'+
                '   --data "')+'"';
                reqElement.style.display='block';

            var resElement=document.querySelector('#fetchtoken ~ .json-response');
            resElement.setAttribute('data-http-status', 'HTTP/'+xhr.status);
            if (Object.keys(blob).length>0) {
                resElement.innerText=JSON.stringify(blob, null, 3);
            } else {
                resElement.innerText=xhr.response.substr(0, 1000);
            }
            resElement.style.display='block';

            if (xhr.status==200) {
                setInput('authcode', '');
                setInput('accesstoken', blob.access_token, true);
                document.querySelector('.authcode-arrow').style.display='none';
                document.querySelector('.accesstoken-arrow').style.display='block';

                if (blob.refresh_token) {
                    document.querySelector('.step.refresh').style.display='block';
                    document.querySelector('input[type="button"]#fetchrefreshtoken').style.display='block';
                    setInput('refreshtoken', blob.refresh_token);
                    document.querySelector('.refreshtoken-arrow').style.display='block';
                } else {
                    document.querySelector('.step.refresh').style.display='none';
                    document.querySelector('input[type="button"]#fetchrefreshtoken').style.display='none';
                    document.querySelector('.refreshtoken-arrow').style.display='none';
                }
            }
        }

        xhr.onerror = function(e) {
            showDialog(e.target.statusText ||
                'The request could not be completed. '+
                'This could be due to a CORS restriction by the server, '+
                'or it could be a network issue.\n\n'+
                'You can resolve CORS-related problems by '+
                'using '+document.location.hostname+' as a proxy server.');
        };

        xhr.send(postData + proxyData);

        setInput('accesstoken', '');
        setInput('refreshtoken', '');
    }


    /*
     *
     * STEP 3 (b): Fetch the access token (client_credentials code flow)
     * 
     */


    function fetchClientCredentialsToken() {
        saveFields();

        if (!validateInputs(['token_url', 'client_credentials_clientid', 'clientsecret'])) { return; }

        const authorization = btoa(getInput('client_credentials_clientid')+':'+getInput('clientsecret'));
        const postData = 'grant_type=client_credentials';

        var postUrl=getInput('token_url');
        var proxyData='';
        if (document.querySelector('input[type="checkbox"]#proxy').checked) {
            postUrl='/proxy';
            proxyData='&proxy_target='+encodeURIComponent(getInput('token_url'));
            incrementRequestCount();
        }

        var xhr = new XMLHttpRequest();
        xhr.open('POST', postUrl);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.setRequestHeader('Authorization', 'Basic '+authorization);

        xhr.onload = function() {
            var blob={};
            try {
                blob=JSON.parse(xhr.response);
            } catch {
                console.log('Could not parse response as JSON.');
            }

            var reqElement=document.querySelector('#fetchtoken ~ .http-request');
            reqElement.innerText='$ curl \\\n'+
                '   --request POST "'+getInput('token_url')+'" \\\n'+
                '   --header "Content-Type: application/x-www-form-urlencoded" \\\n'+
                '   --header "Authorization: Basic '+authorization+'" \\\n'+
                '   --data "'+postData.split("&").join('" \\\n'+
                    '   --data "')+'"';
                reqElement.style.display='block';

            var resElement=document.querySelector('#fetchtoken ~ .json-response');
            resElement.setAttribute('data-http-status', 'HTTP/'+xhr.status);
            if (Object.keys(blob).length>0) {
                resElement.innerText=JSON.stringify(blob, null, 3);
            } else {
                resElement.innerText=xhr.response.substr(0, 1000);
            }
            resElement.style.display='block';

            if (xhr.status==200) {
                setInput('authcode', '');
                setInput('accesstoken', blob.access_token, true);
                document.querySelector('.authcode-arrow').style.display='none';
                document.querySelector('.accesstoken-arrow').style.display='block';

                if (blob.refresh_token) {
                    document.querySelector('.step.refresh').style.display='block';
                    document.querySelector('input[type="button"]#fetchrefreshtoken').style.display='block';
                    setInput('refreshtoken', blob.refresh_token);
                    document.querySelector('.refreshtoken-arrow').style.display='block';
                } else {
                    document.querySelector('.step.refresh').style.display='none';
                    document.querySelector('input[type="button"]#fetchrefreshtoken').style.display='none';
                    document.querySelector('.refreshtoken-arrow').style.display='none';
                }
            }
        }

        xhr.onerror = function(e) {
            showDialog(e.target.statusText ||
                'The request could not be completed. '+
                'This could be due to a CORS restriction by the server, '+
                'or it could be a network issue.\n\n'+
                'You can resolve CORS-related problems by '+
                'using '+document.location.hostname+' as a proxy server.');
        };

        xhr.send(postData + proxyData);

        setInput('accesstoken', '');
        setInput('refreshtoken', '');
    }



    /*
     *
     * STEP 4: Refresh the access token:
     * 
     */

    function refreshAccessToken() {
        saveFields();

        if (!validateInputs(['token_url', 'authcode_clientid', 'clientsecret', 'refreshtoken'])) { return; }

        const postData=
             'client_id='+encodeURIComponent(getInput('authcode_clientid'))+
            '&client_secret='+encodeURIComponent(getInput('clientsecret'))+
            '&refresh_token='+encodeURIComponent(getInput('refreshtoken'))+
            '&grant_type=refresh_token'

        var postUrl=getInput('token_url');
        var proxyData='';
        if (document.querySelector('input[type="checkbox"]#proxy').checked) {
            postUrl='/proxy';
            proxyData='&proxy_target='+encodeURIComponent(getInput('token_url'));
            incrementRequestCount();
        }
        
        var xhr = new XMLHttpRequest();
        xhr.open('POST', postUrl);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

        xhr.onload = function() {
            var blob={};
            try {
                blob=JSON.parse(xhr.response);
            } catch {
                console.log('Could not parse response as JSON.');
            }

            var reqElement=document.querySelector('#fetchrefreshtoken ~ .http-request');
            reqElement.innerText='$ curl \\\n'+
                '   --request POST "/'+getInput('token_url').split('://')[1].split('/').slice(1, 99).join('/')+'" \\\n'+
                '   --header "Content-Type: application/x-www-form-urlencoded" \\\n'+
                '   --data "'+postData.split("&").join('" \\\n'+
                    '   --data "')+'"';
            reqElement.style.display='block';

            var resElement=document.querySelector('#fetchrefreshtoken ~ .json-response');
            resElement.setAttribute('data-http-status', 'HTTP/'+xhr.status);
            if (Object.keys(blob).length>0) {
                resElement.innerText=JSON.stringify(blob, null, 3);
            } else {
                resElement.innerText=xhr.response.substr(0, 1000);
            }
            resElement.style.display='block';

            if (xhr.status==200) {
                setInput('accesstoken', blob.access_token, true);
            }
        }

        xhr.onerror = function(e) {
            showDialog(e.target.statusText ||
                'The request could not be completed. '+
                'This could be due to a CORS restriction by the server, '+
                'or it could be a network issue.\n\n'+
                'You can resolve CORS-related problems by '+
                'using '+document.location.hostname+' as a proxy server.');
        };

        xhr.send(postData + proxyData);

        setInput('accesstoken', '');
    }









    /*
     *
     * When the page loads
     * 
     */

    window.onload = function letsgo() {
        const urlParams = new URLSearchParams(window.location.search);

        document.querySelector('#urlselector').addEventListener('change', (e) => {
            setInput('auth_url', e.target.value.split(';')[0]);
            setInput('token_url', e.target.value.split(';')[1]);
            setInput('scope', e.target.value.split(';')[2]);

            var a=document.querySelector('#application_setup_url');
            if (e.target.value.split(';')[3]) {
                const option=e.target.querySelector('option:checked');
                a.href=e.target.value.split(';')[3];
                a.innerText='Set up your '+option.innerText+' application here.';
                a.style.display='inline';
            } else {
                a.style.display='none';
            }
        });

        document.querySelector('#granttype').addEventListener('change', (e) => {
            document.body.setAttribute('data-grant-type', e.target.value);
        });

        populateFields();
        document.body.setAttribute('data-grant-type', getInput('granttype'));



        document.querySelector('#fetchauth').addEventListener('click', (e) => {
            fetchAuthCode();
        });

        document.querySelector('input[type="button"]#reset').addEventListener('click', (e) => {
            document.querySelectorAll('input[type="text"], input[type="password"], input[type="url"], input[type="checkbox"]').forEach(i => {
                if (i.type=='checkbox') {
                    i.checked=false;
                } else {
                    i.value='';
                }
            });
        });

        document.querySelector('#fetchtoken').addEventListener('click', (e) => {
            switch (getInput('granttype')) {
                case 'auth_code':
                    fetchAccessToken();
                    break;
                case 'client_credentials':
                    fetchClientCredentialsToken();
                    break;
            }
        });

        document.querySelector('#fetchrefreshtoken').addEventListener('click', (e) => {
            switch (getInput('granttype')) {
                case 'auth_code':
                    refreshAccessToken();
                    break;
            }
        });

        document.querySelector('input[type="checkbox"]#proxy').addEventListener('click', (e) => {
            setButtonEnabledDisabled();
            if (e.target.checked) {
                showDialog('Warning: Using '+document.location.hostname+' as a ' +
                    'proxy server will pass your authentication data through '+
                    'that server. Though we will never log your traffic, only '+
                    'check this box if you understand and accept what this means.'
                );
            }
        });

        document.querySelector('dialog input[type="button"]').addEventListener('click', (e) => {
            e.target.parentElement.close();
        });

        document.querySelectorAll('#servername').forEach(e => {
            e.innerText = document.location.hostname;
        });

        document.querySelectorAll('span.info').forEach(i => {
            const rel=i.parentElement.closest('label, span');
            i.addEventListener('click', (e) => {
                e.preventDefault();
                showInformationText(rel);
            });
        });



        // If this is the return URI for fetching an auth code:
        if (urlParams.get('code') && urlParams.get('state')) {
            receiveAuthCode(urlParams);
        }

    };









    /*
     *
     * Helper stuff
     * 
     */

    var requestsInWindow=[];
    var requestLimit=10;    // max number of requests
    var requestWindow=20;  // seconds

    function incrementRequestCount() {
        requestsInWindow.push(Date.now());
        setButtonEnabledDisabled();
        setTimeout(() => {
            if (requestsInWindow.length>0) {
                requestsInWindow.shift(); // remove the oldest timestamp.
                setButtonEnabledDisabled();
            }
        }, 1000*requestWindow);
    }

    function setButtonEnabledDisabled() {
        const isProxied=document.querySelector('input[type="checkbox"]#proxy').checked;

        //console.log('Queue length:', requestsInWindow.length);
        document.querySelectorAll('input#fetchtoken, input#fetchrefreshtoken').forEach((e) => {
            e.disabled=(requestsInWindow.length>=requestLimit && isProxied==true);
        });
    }

    function validateInputs(fields) {
        for (const field of fields) {
            if (getInput(field).trim()=='') {
                showDialog('You need to provide a value for "'+field+'" in order to proceed.');
                return false;
            }
        };
        return true;
    }

    function showInformationText(rel) {
        const comment=Array.from(rel.parentElement.childNodes).filter(e => e.nodeName=='#comment' )[0].data;

        var dialog=document.querySelector('dialog');

        const span=dialog.querySelector('span');
        span.innerHTML=comment;

        dialog.showModal();
        dialog.querySelector('input[type="button"]').focus();
    }

    function showDialog(text) {
        var dialog=document.querySelector('dialog');

        const span=dialog.querySelector('span');
        span.innerText=text;

        dialog.showModal();
        dialog.querySelector('input[type="button"]').focus();
    }

    function generateState() {
        const bytes = new Uint8Array(12);
        window.crypto.getRandomValues(bytes);
        return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    function getInput(id) {
        var inputElement=document.querySelector('input#'+id+', select#'+id)
        if (inputElement.type=='checkbox') {
            return inputElement.checked;
        } else {
            return inputElement.value;
        }
    }

    function setInput(id, value, scrollIntoView) {
        var inputElement=document.querySelector('input#'+id+', select#'+id)
        if (inputElement.type=='checkbox') {
            inputElement.checked=value;
        } else {
            inputElement.value=value;
        }

        if (scrollIntoView) { inputElement.scrollIntoView({ behavior: "smooth", block: "center" }); }
    }

    // Saves the values in the input fields in local storage:
    function saveFields() {
        localStorage.setItem('granttype', getInput('granttype'));

        localStorage.setItem('authurl', getInput('auth_url'));
        localStorage.setItem('clientid', getInput('authcode_clientid') || getInput('client_credentials_clientid'));
        localStorage.setItem('scope', getInput('scope'));
        localStorage.setItem('prompt',
            (getInput('prompt_consent') ? 'consent' : '') + ' ' +
            (getInput('prompt_select_account') ? 'select_account' : ''));
        localStorage.setItem('access_type', getInput('access_type_offline') ? 'offline' : 'online');

        localStorage.setItem('tokenurl', getInput('token_url'));
        localStorage.setItem('clientsecret', getInput('clientsecret'));

        localStorage.setItem('accesstoken', getInput('accesstoken'));
        localStorage.setItem('refreshtoken', getInput('refreshtoken'));
    }

    function populateFields() {
        setInput('granttype', localStorage.getItem('granttype') || 'auth_code');

        setInput('auth_url', localStorage.getItem('authurl'));
        setInput('authcode_clientid', localStorage.getItem('clientid'));
        setInput('client_credentials_clientid', localStorage.getItem('clientid'));
        setInput('scope', localStorage.getItem('scope'));
        setInput('prompt_consent', (localStorage.getItem('prompt')===null ? true : localStorage.getItem('prompt').indexOf('consent'))!=-1);
        setInput('prompt_select_account', (localStorage.getItem('prompt')===null ? false : localStorage.getItem('prompt').indexOf('select_account')!=-1));
        setInput('access_type_offline', (localStorage.getItem('access_type')===null ? true : localStorage.getItem('access_type')=='offline'));

        setInput('token_url', localStorage.getItem('tokenurl'));
    }
