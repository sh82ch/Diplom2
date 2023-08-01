from webbrowser import get

import yaml
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.validators import URLValidator
from django.db import IntegrityError
from django.db.models import Q, Sum, F
from django.http import JsonResponse
from django.shortcuts import render
from rest_framework import status
from rest_framework import authentication, permissions
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from ujson import loads as load_json
from .permissions import IsClient, IsSeller, IsOwner
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from yaml import load as load_yaml, Loader

from .signals import new_user_registered, new_order
from .models import *
from .serializers import *


class CustomAPIView(APIView):
    def get_permissions(self):
        # Instances and returns the dict of permissions that the view requires.
        return {key: [permission() for permission in permissions] for key, permissions in
                self.permission_classes.items()}

    def check_permissions(self, request):
        # Gets the request method and the permissions dict, and checks the permissions defined in the key matching
        # the method.
        method = request.method.lower()
        for permission in self.get_permissions()[method]:
            if not permission.has_permission(request, self):
                self.permission_denied(
                    request, message=getattr(permission, 'message', None)
                )


class UpdateShop(APIView):

    def post(self, request):

        with open("C:\\django\\lusiProject\\myapp\\inputdata\\shop1.yaml") as stream:
            print('Open file shop1.yaml')
            try:
                data = load_yaml(stream, Loader=Loader)
                shop_data = data['shop']
                categories = data['categories']
                goods = data['goods']

                shop, _ = Shop.objects.get_or_create(name=data['shop'])
                print(f'Make shop {data["shop"]}')

                for category_data in categories:
                    category, _ = Category.objects.get_or_create(id=category_data['id'], name=category_data['name'])
                    category.shops.add(shop.id)
                    category.save()

                print('Make cats')

                for good in goods:
                    product, _ = Product.objects.get_or_create(id=good['id'], name=good['name'],
                                                               category_id=good['category'])
                    product_info = ProductInfo.objects.create(
                        product_id=product.id,
                        shop_id=shop.id,
                        model=good['model'],
                        price=good['price'],
                        price_rrc=good['price_rrc'],
                        quantity=good['quantity'],)
                    for name, value in good['parameters'].items():
                        parameter_object, _ = Parameter.objects.get_or_create(name=name)
                        ProductParameter.objects.create(
                            product_info_id=product_info.id,
                            parameter_id=parameter_object.id,
                            value=value)
            except yaml.YAMLError as exc:
                return Response({'status': 'Error', 'message': exc})
        return Response({'status': 'OK'})


class LoginAccount(APIView):
    """
    Класс для авторизации пользователей
    """

    def post(self, request, *args, **kwargs):
        if {'email', 'password'}.issubset(request.data):
            user = authenticate(request, email=request.data['email'], password=request.data['password'])

            if user is not None:
                if user.is_active:
                    token, _ = Token.objects.get_or_create(user=user)

                    return Response({'status': True, 'token': token.key}, status=200)

            return Response(data={'status': False, 'errors': 'Не удалось авторизовать'}, status=400)

        return Response({'status': False, 'errors': 'Не указаны все необходимые аргументы'}, status=400)


class ConfirmAccount(APIView):
    """
    Класс для подтверждения почтового адреса
    """
    # Регистрация методом POST
    def post(self, request, *args, **kwargs):

        # проверяем обязательные аргументы
        if {'email', 'token'}.issubset(request.data):

            token = ConfirmEmailToken.objects.filter(user__email=request.data['email'],
                                                     key=request.data['token']).first()
            if token:
                token.user.is_active = True
                token.user.save()
                token.delete()
                return JsonResponse({'Status': True})
            else:
                return JsonResponse({'Status': False, 'Errors': 'Неправильно указан токен или email'})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

class RegisterAccount(APIView):
    """
    Для регистрации покупателей
    """

    # Регистрация методом POST
    def post(self, request, *args, **kwargs):

        # проверяем обязательные аргументы
        if {'first_name', 'last_name', 'email', 'password', 'company', 'position'}.issubset(request.data):
            errors = {}

            # проверяем пароль на сложность

            try:
                validate_password(request.data['password'])
            except Exception as password_error:
                error_array = []
                # noinspection PyTypeChecker
                for item in password_error:
                    error_array.append(item)
                return JsonResponse({'status': False, 'Errors': {'password': error_array}})
            else:
                # проверяем данные для уникальности имени пользователя
                user_serializer = UserSerializer(data=request.data)
                if user_serializer.is_valid():
                    # сохраняем пользователя
                    user = user_serializer.save()
                    user.set_password(request.data['password'])
                    user.save()
                    new_user_registered.send(sender=self.__class__, user_id=user.id)
                    return JsonResponse({'status': True})
                else:
                    return JsonResponse({'status': False, 'Errors': user_serializer.errors})

        return JsonResponse({'status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class ShopView(ListAPIView):
    """
    Класс для просмотра списка магазинов
    """
    queryset = Shop.objects.filter(state=True)
    serializer_class = ShopSerializer


class ProductInfoByPKView(APIView):
    """
    Класс для просмотра списка товаров
    """
    def get(self, request, *args, **kwargs):
        pk = self.kwargs.get('pk')
        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query = query & Q(shop_id=shop_id)

        if category_id:
            query = query & Q(product__category_id=category_id)

        # фильтруем и отбрасываем дуликаты
        queryset = ProductInfo.objects.filter(
            query).select_related(
            'shop', 'product__category').prefetch_related(
            'product_parameters__parameter').distinct()

        if pk is not None:
            try:
                product = ProductInfo.objects.get(product_id=pk)
                serializer = ProductInfoSerializer(product)
                return Response(serializer.data)
            except:
                return Response({'error': 'Product not found'})


        return Response({'error': 'pk error'})

class ProductInfoView(APIView):
    """
    Класс для просмотра списка товаров
    """
    def get(self, request, *args, **kwargs):
        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query = query & Q(shop_id=shop_id)

        if category_id:
            query = query & Q(product__category_id=category_id)

        # фильтруем и отбрасываем дуликаты
        queryset = ProductInfo.objects.filter(
            query).select_related(
            'shop', 'product__category').prefetch_related(
            'product_parameters__parameter').distinct()

        serializer = ProductInfoSerializer(queryset, many=True)

        return Response(serializer.data)


@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
class BasketView(APIView):
    """
    Класс для работы с корзиной пользователя
    """
    # получить корзину
    def get(self, request, *args, **kwargs):
        basket = Order.objects.filter(
            user_id=request.user.id, state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(basket, many=True)
        return Response(serializer.data)

    # редактировать корзину
    def post(self, request, *args, **kwargs):
        items = request.data.get('items')

        if items:
            basket, _ = Order.objects.update_or_create(user_id=request.user.id, state='basket')
            objects_created = 0
            for order_item in items:
                item , created = OrderItem.objects.update_or_create(
                    order_id=basket.id,
                    product_info_id = order_item['product_info'],
                    defaults={'quantity': order_item['quantity']}
                )
                objects_created += 1
            return Response({'Status': True, 'Создано объектов': objects_created})
        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    def delete(self, request, *args, **kwargs):
        items = request.data.get('items')

        if items:
            basket, _ = Order.objects.update_or_create(user_id=request.user.id, state='basket')
            objects_removed = 0
            for order_item in items:
                try:
                    item = OrderItem.objects.get(
                        order_id=basket.id,
                        product_info_id=order_item['product_info'],
                    )
                except:
                    return Response({'Status': False, 'Errors': 'Не существует такого товара в корзине'})
                item.delete()
                objects_removed += 1
            return Response({'Status': True, 'Удалено объектов': objects_removed})
        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
class BasketConfirmView(APIView):
    """
    Класс для подтверждения заказа
    """
    # подтвердить заказ с определенным контактным адресом
    def post(self, request, *args, **kwargs):
        user = request.user
        basket, created = Order.objects.get_or_create(user_id=user.id, state='basket')

        raw_data = request.data
        raw_data['user'] = user.id  # Используйте 'user', а не 'user_id' для создания связи с User

        serializer = ContactSerializer(data=raw_data)
        if serializer.is_valid():
            contact = serializer.save()  # Сохраняем созданный/обновленный объект Contact
            basket.contact = contact  # Связываем заказ с контактным адресом
            basket.save()  # Сохраняем изменения в объекте Order
            return Response({'Status': True, 'Message': 'Order confirmed successfully.'})
        else:
            return Response({'Status': False, 'Errors': serializer.errors})


@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
class OrderDoneView(APIView):
    def post(self, request, *args, **kwargs):
        order_id = request.data['order_id']
        try:
            order = Order.objects.get(id=order_id)
        except:
            return Response({"error":f"Invalid order id {order_id}"})

        order.state='done'
        order.save()
        return Response({"Order":f"Order {order_id} Done!"})

@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
class OrderView(APIView):
    """
    Класс для просмотра заказов
    """

    # подтвердить заказ с определенным контактным адресом
    def get(self, request, *args, **kwargs):
        user = request.user

        orders = Order.objects.filter(user_id=user.id)

        response_body = {'done':[]}

        done = Order.objects.filter(
            user_id=request.user.id, state='done').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(done, many=True)

        response_body['done'] = serializer.data


        return Response({'Orders': response_body})

