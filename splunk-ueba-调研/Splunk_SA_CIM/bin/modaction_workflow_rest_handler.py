try:
    import http.client as http_client
except ImportError:
    import httplib as http_client
import json
import logging
import re

import splunk
import splunk.rest
from splunk.persistconn.application import PersistentServerConnectionApplication

try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote


logger = logging.getLogger('modaction_workflow_rest_handler')


class ModularActionWorkflowError(ValueError):
    """Raised when a workflow-action request is invalid."""


class ModularActionWorkflowExecutionError(RuntimeError):
    """Raised when a validated workflow action cannot be executed."""


class ModularActionWorkflowRestHandler(
        PersistentServerConnectionApplication):
    ACTION_INVOCATIONS = 'invocations'
    ACTION_RESULTS = 'results'
    ACTIONS = frozenset((ACTION_INVOCATIONS, ACTION_RESULTS))

    MAX_IDENTIFIER_LENGTH = 256
    MAX_CONTEXT_LENGTH = 256

    IDENTIFIER_PATTERN = re.compile(r'\A[A-Za-z0-9_.-]+\Z', re.ASCII)
    CONTEXT_PATTERN = re.compile(r'\A[A-Za-z0-9_.-]+\Z', re.ASCII)

    SEARCH_TEMPLATES = {
        ACTION_INVOCATIONS: (
            'search tag=modaction ((sid="{sid}" rid="{rid}") OR '
            '(orig_sid="{sid}" orig_rid="{rid}"))'
        ),
        ACTION_RESULTS: (
            'search tag=modaction_result orig_sid="{sid}" orig_rid="{rid}"'
        ),
    }

    REQUIRED_FIELDS = (
        'action',
        'sid',
        'rid',
        'source_sid',
        'namespace',
    )

    def __init__(self, command_line, command_arg):
        super(ModularActionWorkflowRestHandler, self).__init__()

    @staticmethod
    def response(payload, status):
        return {
            'status': status,
            'payload': payload,
        }

    @classmethod
    def error(cls, message, status):
        return cls.response({
            'success': False,
            'messages': [{
                'type': 'ERROR',
                'message': message,
            }],
        }, status)

    def handle(self, in_string):
        try:
            args = json.loads(in_string)
        except (TypeError, ValueError):
            return self.error('Invalid request', http_client.BAD_REQUEST)

        if not isinstance(args, dict):
            return self.error('Invalid request', http_client.BAD_REQUEST)

        method = args.get('method', '')
        if not isinstance(method, str):
            return self.error('Invalid request', http_client.BAD_REQUEST)
        method = method.lower()
        handler = getattr(self, 'handle_' + method, None)
        if not callable(handler):
            return self.error(
                'Invalid method for this endpoint',
                http_client.METHOD_NOT_ALLOWED,
            )

        try:
            return handler(args)
        except ModularActionWorkflowError as exc:
            return self.error(str(exc), http_client.BAD_REQUEST)
        except ModularActionWorkflowExecutionError:
            logger.exception('Workflow action execution failed')
            return self.error(
                'Unable to execute workflow action',
                http_client.INTERNAL_SERVER_ERROR,
            )
        except splunk.RESTException:
            logger.exception('Splunk REST request failed')
            return self.error(
                'Unable to execute workflow action',
                http_client.INTERNAL_SERVER_ERROR,
            )
        except Exception:
            logger.exception('Unexpected workflow action failure')
            return self.error(
                'Unable to execute workflow action',
                http_client.INTERNAL_SERVER_ERROR,
            )

    @classmethod
    def get_single_form_value(cls, form, name):
        if not isinstance(form, (list, tuple)):
            raise ModularActionWorkflowError('Invalid request form')

        values = []
        for item in form:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise ModularActionWorkflowError('Invalid request form')
            if item[0] == name:
                values.append(item[1])

        if len(values) != 1:
            raise ModularActionWorkflowError(
                'Expected exactly one {0} value'.format(name)
            )

        return values[0]

    @classmethod
    def validate_action(cls, value):
        if not isinstance(value, str) or value not in cls.ACTIONS:
            raise ModularActionWorkflowError('Invalid workflow action')
        return value

    @classmethod
    def validate_identifier(cls, value, name):
        return cls._validate_string(
            value,
            name,
            cls.IDENTIFIER_PATTERN,
            cls.MAX_IDENTIFIER_LENGTH,
        )

    @classmethod
    def validate_context(cls, value, name):
        value = cls._validate_string(
            value,
            name,
            cls.CONTEXT_PATTERN,
            cls.MAX_CONTEXT_LENGTH,
        )
        if value in ('.', '..'):
            raise ModularActionWorkflowError(
                'Invalid {0} value'.format(name)
            )
        return value

    @staticmethod
    def _validate_string(value, name, pattern, max_length):
        if not isinstance(value, str):
            raise ModularActionWorkflowError(
                '{0} must be a string'.format(name)
            )
        if not value or len(value) > max_length:
            raise ModularActionWorkflowError(
                'Invalid {0} length'.format(name)
            )
        if pattern.fullmatch(value) is None:
            raise ModularActionWorkflowError(
                'Invalid {0} characters'.format(name)
            )
        return value

    @classmethod
    def parse_request(cls, form):
        values = {
            name: cls.get_single_form_value(form, name)
            for name in cls.REQUIRED_FIELDS
        }

        return {
            'action': cls.validate_action(values['action']),
            'sid': cls.validate_identifier(values['sid'], 'sid'),
            'rid': cls.validate_identifier(values['rid'], 'rid'),
            'source_sid': cls.validate_context(
                values['source_sid'], 'source_sid'
            ),
            'namespace': cls.validate_context(
                values['namespace'], 'namespace'
            ),
        }

    @classmethod
    def build_search(cls, action, sid, rid):
        valid_action = cls.validate_action(action)
        valid_sid = cls.validate_identifier(sid, 'sid')
        valid_rid = cls.validate_identifier(rid, 'rid')

        return cls.SEARCH_TEMPLATES[valid_action].format(
            sid=valid_sid,
            rid=valid_rid,
        )

    @staticmethod
    def _get_source_time(content, name):
        effective_names = {
            'earliest_time': 'searchEarliestTime',
            'latest_time': 'searchLatestTime',
        }

        value = content.get(effective_names[name])
        if value not in (None, ''):
            if (
                isinstance(value, bool)
                or not isinstance(value, (str, int, float))
            ):
                raise ModularActionWorkflowExecutionError(
                    'Invalid source search time range'
                )
            value = str(value)

        if value in (None, ''):
            dispatch = content.get('dispatch')
            value = (
                dispatch.get(name) if isinstance(dispatch, dict) else None
            )
        if value in (None, ''):
            value = content.get('dispatch.' + name)
        if value in (None, ''):
            request = content.get('request')
            value = (
                request.get(name) if isinstance(request, dict) else None
            )
        if value in (None, ''):
            value = content.get('request.' + name)
        if value in (None, ''):
            return None
        if not isinstance(value, str) or len(value) > 256:
            raise ModularActionWorkflowExecutionError(
                'Invalid source search time range'
            )
        return value

    @classmethod
    def get_source_time_range(cls, source_sid, session_key):
        source_job_uri = '/services/search/jobs/{0}'.format(
            quote(source_sid, safe=''),
        )
        response, content = splunk.rest.simpleRequest(
            source_job_uri,
            getargs={'output_mode': 'json'},
            sessionKey=session_key,
            raiseAllErrors=True,
        )

        if response.status != http_client.OK:
            raise ModularActionWorkflowExecutionError(
                'Unable to read source search context'
            )

        try:
            entries = json.loads(content)['entry']
            job_content = entries[0]['content']
        except (KeyError, IndexError, TypeError, ValueError):
            raise ModularActionWorkflowExecutionError(
                'Unable to read source search context'
            )

        if len(entries) != 1 or not isinstance(job_content, dict):
            raise ModularActionWorkflowExecutionError(
                'Unable to read source search context'
            )

        time_range = {}
        for name in ('earliest_time', 'latest_time'):
            value = cls._get_source_time(job_content, name)
            if value is not None:
                time_range[name] = value

        return time_range

    @staticmethod
    def dispatch_search(search, namespace, owner, session_key,
                        time_range=None):
        jobs_uri = '/servicesNS/{0}/{1}/search/jobs'.format(
            quote(owner, safe=''),
            quote(namespace, safe=''),
        )
        post_args = {
            'output_mode': 'json',
            'search': search,
        }
        if time_range:
            post_args.update(time_range)

        response, content = splunk.rest.simpleRequest(
            jobs_uri,
            postargs=post_args,
            sessionKey=session_key,
            raiseAllErrors=True,
        )

        if response.status != http_client.CREATED:
            raise ModularActionWorkflowExecutionError(
                'Unable to dispatch workflow search'
            )

        try:
            sid = json.loads(content)['sid']
        except (KeyError, TypeError, ValueError):
            raise ModularActionWorkflowExecutionError(
                'Unable to dispatch workflow search'
            )

        try:
            return ModularActionWorkflowRestHandler.validate_context(
                sid,
                'search sid',
            )
        except ModularActionWorkflowError:
            raise ModularActionWorkflowExecutionError(
                'Invalid dispatched search sid'
            )

    def handle_post(self, args):
        session = args.get('session') or {}
        session_key = session.get('authtoken')
        owner = session.get('user')
        if not isinstance(session_key, str) or not session_key:
            return self.error(
                'Authentication is required',
                http_client.UNAUTHORIZED,
            )
        if not isinstance(owner, str) or not owner:
            return self.error(
                'Authentication is required',
                http_client.UNAUTHORIZED,
            )

        request = self.parse_request(args.get('form'))
        search = self.build_search(
            request['action'],
            request['sid'],
            request['rid'],
        )
        time_range = self.get_source_time_range(
            request['source_sid'],
            session_key,
        )
        sid = self.dispatch_search(
            search,
            request['namespace'],
            owner,
            session_key,
            time_range,
        )

        return self.response({
            'success': True,
            'sid': sid,
            'namespace': request['namespace'],
        }, http_client.CREATED)
