from django.http import HttpResponse


class CustomErrorMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            response = self.get_response(request)
        except Exception as e:
            # Handle the exception here
            response = HttpResponse(f"An error occurred: {e}", status=500)
        return response
