#
# Copyright 2019 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

"""View for principal access."""
from management.cache import AccessCache
from management.querysets import get_access_queryset
from management.role.model import Permission
from management.role.serializer import AccessSerializer
from management.utils import APPLICATION_KEY, get_principal_from_request, validate_and_get_key
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework.views import APIView

SCOPE_KEY = "scope"
ACCOUNT_SCOPE = "account"
PRINCIPAL_SCOPE = "principal"

# Mapping of input parameter to query parameter.
PERMISSION_FILTERS_MAPPING = {APPLICATION_KEY: "app__in", "resource_type": "resource__in", "verb": "operation__in"}


class AccessView(APIView):
    """Obtain principal access list."""

    """
    @api {get} /api/v1/access/   Obtain principal access list
    @apiName getPrincipalAccess
    @apiGroup Access
    @apiVersion 1.0.0
    @apiDescription Obtain principal access list

    @apiHeader {String} token User authorization token

    @apiParam (Query) {String} application Application name
    @apiParam (Query) {Number} offset Parameter for selecting the start of data (default is 0).
    @apiParam (Query) {Number} limit Parameter for selecting the amount of data (default is 10).

    @apiSuccess {Object} meta The metadata for pagination.
    @apiSuccess {Object} links  The object containing links of results.
    @apiSuccess {Object[]} data  The array of results.
    @apiSuccessExample {json} Success-Response:
        HTTP/1.1 20O OK
        {
            'meta': {
                'count': 1
            }
            'links': {
                'first': /api/v1/access/?offset=0&limit=10&application=app,
                'next': None,
                'previous': None,
                'last': /api/v1/groups/?offset=0&limit=10&application=app
            },
            "data": [
                {
                    "permission": "app:*:read",
                    "resourceDefinitions": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.condition",
                                "value": "value1",
                                "operation": "equal"
                            }
                        }
                    ]
                }
            ]
        }
    """

    serializer_class = AccessSerializer
    pagination_class = api_settings.DEFAULT_PAGINATION_CLASS
    permission_classes = (AllowAny,)

    def get_queryset(self):
        """Define the query set."""
        return get_access_queryset(self.request)

    def get(self, request):
        """Provide access data for principal."""
        scope = validate_and_get_key(
            request.query_params, SCOPE_KEY, [ACCOUNT_SCOPE, PRINCIPAL_SCOPE], PRINCIPAL_SCOPE
        )

        if scope == ACCOUNT_SCOPE:
            return self.obtain_paginated_account_permissions(request)

        app = request.query_params.get(APPLICATION_KEY)
        principal = get_principal_from_request(request)
        cache = AccessCache(request.tenant.schema_name)
        access_policy = cache.get_policy(principal.uuid, app)
        if access_policy is None:
            queryset = self.get_queryset()
            access_policy = self.serializer_class(queryset, many=True).data
            cache.save_policy(principal.uuid, app, access_policy)
        page = self.paginate_queryset(access_policy)

        if page is not None:
            return self.get_paginated_response(access_policy)
        return Response({"data": access_policy})

    @property
    def paginator(self):
        """Return the paginator instance associated with the view, or `None`."""
        if not hasattr(self, "_paginator"):
            self._paginator = self.pagination_class()
            if self.pagination_class is None or "limit" not in self.request.query_params:
                self._paginator.default_limit = self._paginator.max_limit
        return self._paginator

    def paginate_queryset(self, queryset):
        """Return a single page of results, or `None` if pagination is disabled."""
        if self.paginator is None:
            return None
        return self.paginator.paginate_queryset(queryset, self.request, view=self)

    def get_paginated_response(self, data):
        """Return a paginated style `Response` object for the given output data."""
        assert self.paginator is not None
        return self.paginator.get_paginated_response(data)

    def obtain_paginated_account_permissions(self, request):
        """Return filtered permissions."""
        filters = {}
        for key in PERMISSION_FILTERS_MAPPING.keys():
            context = request.query_params.get(key)
            if context:
                filters[PERMISSION_FILTERS_MAPPING.get(key)] = context.split(",")

        query_set = Permission.objects.filter(**filters).values_list("permission", flat=True)
        page = self.paginate_queryset(query_set)

        if page is not None:
            return self.get_paginated_response(page)

        return Response({"data": query_set})
