package handlers

import (
	"log/slog"
	"strconv"

	"github.com/ghostsecurity/reaper/internal/config"
	"github.com/ghostsecurity/reaper/internal/database/models"
	"github.com/ghostsecurity/reaper/internal/service"
	"github.com/ghostsecurity/reaper/internal/tools/fuzz"
	"github.com/ghostsecurity/reaper/internal/types"
	"github.com/gofiber/fiber/v2"
)

func (h *Handler) GetEndpoints(c *fiber.Ctx) error {
	endpoints := []models.Endpoint{}
	h.db.Find(&endpoints)

	return c.JSON(endpoints)
}

func (h *Handler) GetEndpoint(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	endpoint := models.Endpoint{}
	h.db.First(&endpoint, id)

	return c.JSON(endpoint)
}

func (h *Handler) CreateEndpoint(c *fiber.Ctx) error {
	var endpointInput service.EndpointInput

	if err := c.BodyParser(&endpointInput); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if endpointInput.Hostname == "" || endpointInput.Path == "" || endpointInput.Method == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "hostname, path, and method are required"})
	}

	endpoint, err := service.CreateOrUpdateEndpoint(h.db, endpointInput)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(endpoint)
}

func (h *Handler) CreateAttack(c *fiber.Ctx) error {
	var atk struct {
		EndpointID uint     `json:"endpoint_id"`
		Params     []string `json:"params"`
	}

	if err := c.BodyParser(&atk); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if atk.EndpointID < 1 || len(atk.Params) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "endpoint_id and params are required"})
	}

	attackConfig := config.SharedAttackConfig
	// Modify enabled the attacks
	attackConfig.HP = false
	attackConfig.LP = false
	attackConfig.NP = false
	attackConfig.RPP = false
	attackConfig.BPP = false
	attackConfig.MR = false
	attackConfig.RPW = false
	attackConfig.BPW = false
	attackConfig.RPS = false
	attackConfig.RPSPP = false
	attackConfig.JSON = false
	attackConfig.FUZZ = true
	attackConfig.ALL = false

	// get hostname from endpoint
	endpoint := models.Endpoint{}
	err := h.db.First(&endpoint, atk.EndpointID).Error
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "endpoint not found"})
	}

	go func() {

		err := fuzz.CreateAttack(endpoint.Hostname, atk.Params, h.pool, h.db, 0, false, attackConfig)
		if err != nil {
			slog.Error("[create attack]", "msg", "error creating attack", "error", err)
		}
	}()

	return c.JSON(fiber.Map{"status": "ok"})
}

func (h *Handler) DeleteAttackResults(c *fiber.Ctx) error {
	// TODO: delete by endpoint id
	// id, err := strconv.Atoi(c.Params("id"))
	// if err != nil {
	// 	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	// }

	res := h.db.Delete(&models.FuzzResult{})
	if res.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": res.Error.Error()})
	}

	m := &types.AttackResultMessage{
		Type: types.MessageTypeAttackResultClear,
	}

	h.pool.Broadcast <- m

	return c.JSON(fiber.Map{"status": "ok", "deleted": res.RowsAffected})
}
