from rest_framework.response import Response
from rest_framework import serializers
from rest_framework import status
from rest_framework.views import APIView
from django.db.models import Q, F, Value, CharField, Func
from django_filters import rest_framework as filters
from django.db.models.functions import Concat, Lower
from rest_framework import filters as rest_filters
import re
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status


class BaseSerializer(serializers.ModelSerializer):
    pass


class NormalizeSpaces(Func):
    function = "REGEXP_REPLACE"
    template = "%(function)s(%(expressions)s, '\\s+', ' ', 'g')"
    output_field = CharField()


class BaseAPIView(APIView):
    model = None
    serializer_class = None
    lookup_field = "pk"
    allowed_methods = ["GET_LIST", "GET_DETAIL", "POST", "PUT", "PATCH", "DELETE"]

     # ---- Utility ----
    def get_queryset(self):
        if not self.model:
            raise ValueError("You must define 'model' on the view")
        return self.model.objects.all()

    def get_object(self, pk):
        return get_object_or_404(self.get_queryset(), **{self.lookup_field: pk})

    def normalize_text(self, text):
        return re.sub(r"\s+", " ", text.strip()).lower()

    def _check_method(self, method):
        if method not in self.allowed_methods:
            return Response(
                {"detail": f"{method} not allowed"},
                status=status.HTTP_405_METHOD_NOT_ALLOWED,
            )
        return None

    def filter_queryset(self, queryset, search_fields=None):
        if search_fields is None:
            search_fields = getattr(self, "search_fields", [])

        # Apply DRF backends first
        for backend in [filters.DjangoFilterBackend, rest_filters.SearchFilter]:
            queryset = backend().filter_queryset(self.request, queryset, self)

        search = self.request.query_params.get("search", "").strip()
        if not search:
            return queryset

        normalized_search = self.normalize_text(search)
        query = Q()

        # Annotate each field with normalized version
        for field in search_fields:
            norm_field_name = f"normalized_{field}"
            queryset = queryset.annotate(
                **{
                    f"{field}_raw": F(field),
                    norm_field_name: Lower(NormalizeSpaces(F(f"{field}_raw"))),
                }
            )
            query |= Q(**{f"{norm_field_name}__icontains": normalized_search})

        # Special case: full_name support if first_name and last_name exist
        if "first_name" in search_fields and "last_name" in search_fields:
            queryset = queryset.annotate(
                full_name_raw=Concat(
                    F("first_name"),
                    Value(" "),
                    F("last_name"),
                    output_field=CharField(),
                ),
                normalized_full_name=Lower(NormalizeSpaces(F("full_name_raw"))),
            )
            query |= Q(normalized_full_name__icontains=normalized_search)
        
        elif "user__first_name" in search_fields and "user__last_name" in search_fields:
            queryset = queryset.annotate(
                full_name_raw=Concat(
                    F("user__first_name"),
                    Value(" "),
                    F("user__last_name"),
                    output_field=CharField(),
                ),
                normalized_full_name=Lower(NormalizeSpaces(F("full_name_raw"))),
            )
            query |= Q(normalized_full_name__icontains=normalized_search)

        return queryset.filter(query).distinct()
    
    # ---- CRUD METHODS ----
    def get(self, request, pk=None):
        try:
            if pk:
                blocked = self._check_method("GET_DETAIL")
                if blocked: return blocked
                instance = self.get_object(pk)
                serializer = self.serializer_class(instance)
            else:
                blocked = self._check_method("GET_LIST")
                if blocked: return blocked
                queryset = self.get_queryset()
                serializer = self.serializer_class(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request):
        try:
            blocked = self._check_method("POST")
            if blocked: return blocked

            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                # if hasattr(self.model, "created_by"):
                #     serializer.save(created_by=request.user)
                # else:
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        try:
            blocked = self._check_method("PUT")
            if blocked: return blocked

            instance = self.get_object(pk)
            serializer = self.serializer_class(instance, data=request.data)
            if serializer.is_valid():
                # if hasattr(self.model, "updated_by"):
                #     serializer.save(updated_by=request.user)
                # else:
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        try:
            blocked = self._check_method("PATCH")
            if blocked: return blocked

            instance = self.get_object(pk)
            serializer = self.serializer_class(instance, data=request.data, partial=True)
            if serializer.is_valid():
                # if hasattr(self.model, "updated_by"):
                #     serializer.save(updated_by=request.user)
                # else:
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        try:
            blocked = self._check_method("DELETE")
            if blocked: return blocked

            instance = self.get_object(pk)
            instance.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)