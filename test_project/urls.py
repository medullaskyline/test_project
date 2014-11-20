from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
# from testing_app.views import AuthComplete, LoginError

urlpatterns = patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^testing_app/', include('testing_app.urls')),
    url(r'^admin/', include(admin.site.urls)),
    # url(r'^complete/(?P<backend>[^/]+)/$', AuthComplete.as_view()),  #new
    # url(r'^login-error/$', LoginError.as_view()),  #new
    # url(r'', include('social_auth.urls')),  #new
)

if settings.DEBUG:
    urlpatterns += patterns(
        'django.views.static',
        (r'media/(?P<path>.*)',
        'serve',
        {'document_root': settings.MEDIA_ROOT}),
    )
else:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
