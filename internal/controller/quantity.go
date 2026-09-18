package controller

import "k8s.io/apimachinery/pkg/api/resource"

type resourceQuantity = resource.Quantity

func parseQuantity(s string) (resource.Quantity, error) { return resource.ParseQuantity(s) }
