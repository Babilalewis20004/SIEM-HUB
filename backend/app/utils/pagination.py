"""Shared pagination for list routes that return {total, page, per_page, items}."""
from flask import request


def get_pagination_params(default_per_page=50, max_per_page=200):
    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(max(int(request.args.get("per_page", default_per_page)), 1), max_per_page)
    return page, per_page


def paginate(query, serializer=lambda item: item):
    page, per_page = get_pagination_params()
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [serializer(item) for item in items],
    }
