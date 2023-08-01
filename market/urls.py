from django.urls import path
from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm
from market.views import *

app_name='market'
urlpatterns = [
    path('partner/update', UpdateShop.as_view(), name='shop-update'),
    path('partner/order_confirm',OrderDoneView.as_view(),name='shop-orderdone'),
    path('user/login', LoginAccount.as_view(), name='user-login'),
    path('user/register',RegisterAccount.as_view(),name='user-register'),
    path('user/confirm',ConfirmAccount.as_view(),name='user-emailconfirm'),
    path('user/basket',BasketView.as_view(),name='user-basket'),
    path('user/orders',OrderView.as_view(),name='user-orderhistory'),
    path('user/basket/confirm',BasketConfirmView.as_view(),name='user-basketconfirm'),
    path('market/products',ProductInfoView.as_view(),name='market-products'),
    path('market/products/<int:pk>',ProductInfoByPKView.as_view(),name='market-oneproduct'),
]
