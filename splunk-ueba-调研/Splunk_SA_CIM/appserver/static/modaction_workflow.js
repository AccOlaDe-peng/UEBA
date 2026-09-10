(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory;
    } else if (typeof require === 'function') {
        require([
            'jquery',
        ], function ($) {
            factory(root, $, true);
        });
    }
}(typeof self !== 'undefined' ? self : this, function (root, $, autoStart) {
    'use strict';

    var REQUIRED_PARAMETERS = [
        'action',
        'sid',
        'rid',
        'source_sid',
        'namespace',
    ];
    var STATUS_ELEMENT_ID = 'modaction-workflow-status';
    var GENERIC_ERROR_MESSAGE = (
        'Unable to open this workflow search because the event contains '
        + 'invalid identifiers.'
    );

    function getPathPrefix(pathname) {
        var path = pathname || '';
        var appIndex = path.lastIndexOf('/app/');
        return appIndex === -1 ? '' : path.slice(0, appIndex);
    }

    function parseParameters(search) {
        var query = new URLSearchParams(search || '');
        var result = {};

        REQUIRED_PARAMETERS.forEach(function (name) {
            var values = query.getAll(name);
            if (values.length !== 1 || values[0] === '') {
                throw new Error('Invalid workflow launcher parameters');
            }
            result[name] = values[0];
        });

        return result;
    }

    function getFormKey() {
        if (root.$C && typeof root.$C.FORM_KEY === 'string'
                && root.$C.FORM_KEY) {
            return root.$C.FORM_KEY;
        }

        var cookies = (root.document.cookie || '').split(';');
        for (var index = 0; index < cookies.length; index += 1) {
            var cookie = cookies[index].trim();
            if (cookie.indexOf('splunkweb_csrf_token_') === 0) {
                var separator = cookie.indexOf('=');
                if (separator !== -1 && cookie.slice(separator + 1)) {
                    return cookie.slice(separator + 1);
                }
            }
        }

        throw new Error('Missing Splunk form key');
    }

    function buildEndpointUrl() {
        return getPathPrefix(root.location.pathname)
            + '/splunkd/__raw/servicesNS/nobody/Splunk_SA_CIM/'
            + 'alerts/modaction_workflow';
    }

    function buildRedirectUrl(namespace, sid) {
        return getPathPrefix(root.location.pathname)
            + '/app/' + encodeURIComponent(namespace)
            + '/search?sid=' + encodeURIComponent(sid);
    }

    function setStatus(message, state) {
        var element = root.document.getElementById(STATUS_ELEMENT_ID);
        if (element) {
            element.textContent = message;
            element.setAttribute('data-state', state);
        }
    }

    function postWorkflow(parameters) {
        var formKey = getFormKey();
        var body = new URLSearchParams(parameters);
        body.set('splunk_form_key', formKey);

        return root.fetch(buildEndpointUrl(), {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': (
                    'application/x-www-form-urlencoded; charset=UTF-8'
                ),
                'X-Requested-With': 'XMLHttpRequest',
                'X-Splunk-Form-Key': formKey,
            },
            body: body.toString(),
        }).then(function (response) {
            if (!response.ok) {
                throw new Error('Workflow endpoint rejected the request');
            }
            return response.json();
        }).then(function (payload) {
            if (!payload || payload.success !== true
                    || typeof payload.sid !== 'string' || !payload.sid
                    || typeof payload.namespace !== 'string'
                    || !payload.namespace) {
                throw new Error('Invalid workflow endpoint response');
            }
            return payload;
        });
    }

    function start() {
        setStatus('Opening the workflow search…', 'loading');

        try {
            var parameters = parseParameters(root.location.search);
            return postWorkflow(parameters).then(function (payload) {
                root.location.replace(buildRedirectUrl(
                    payload.namespace,
                    payload.sid
                ));
                return payload;
            }).catch(function () {
                setStatus(GENERIC_ERROR_MESSAGE, 'error');
                return null;
            });
        } catch (error) {
            setStatus(GENERIC_ERROR_MESSAGE, 'error');
            return Promise.resolve(null);
        }
    }

    if (autoStart) {
        $(start);
    }

    return {
        GENERIC_ERROR_MESSAGE: GENERIC_ERROR_MESSAGE,
        buildEndpointUrl: buildEndpointUrl,
        buildRedirectUrl: buildRedirectUrl,
        parseParameters: parseParameters,
        postWorkflow: postWorkflow,
        start: start,
    };
}));
