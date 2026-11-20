package repo

import (
	"agentflow/internal/secretbox"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// botCredentialRow keeps a notification bot's secret. With a key configured
// the column holds a secretbox envelope bound to the bot ID; legacy rows hold
// the secret in plaintext.
type botCredentialRow struct {
	BotID  string `gorm:"primaryKey;size:191"`
	Secret string `gorm:"column:ciphertext;type:text;not null"`
}

func (botCredentialRow) TableName() string { return "user_bot_credentials" }

func botCredentialAAD(botID string) []byte {
	return secretAAD("user_bot_credentials", "ciphertext", botID)
}

// BotCredential returns a bot's secret. A sealed secret that cannot be
// opened is an error wrapping ErrStoredSecretsUnreadable, never "".
func (r *UsersRepo) BotCredential(botID string) (string, error) {
	var row botCredentialRow
	err := r.DB.Where("bot_id = ?", botID).First(&row).Error
	if err != nil {
		return "", err
	}
	return openText(r.secrets, botCredentialAAD(botID), row.Secret)
}

func (r *UsersRepo) putBotCredential(tx *gorm.DB, id, secret string) error {
	stored, err := sealText(r.secrets, botCredentialAAD(id), secret)
	if err != nil {
		return err
	}
	return tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&botCredentialRow{BotID: id, Secret: stored}).Error
}
func (r *UsersRepo) deleteBotCredential(tx *gorm.DB, id string) error {
	return tx.Where("bot_id = ?", id).Delete(&botCredentialRow{}).Error
}

// botCredentialsPass is the user_bot_credentials counterpart of
// ConnectionsRepo.connectionSecretsPass.
func (r *UsersRepo) botCredentialsPass(rewrite, dryRun bool) (SecretsReport, error) {
	report := SecretsReport{Table: "user_bot_credentials"}
	err := r.DB.Transaction(func(tx *gorm.DB) error {
		var rows []botCredentialRow
		q := tx.Order("bot_id")
		if rewrite && !dryRun {
			q = r.locking(q)
		}
		if err := q.Find(&rows).Error; err != nil {
			return err
		}
		for _, row := range rows {
			aad := botCredentialAAD(row.BotID)
			isSealed := secretbox.IsSealed(row.Secret)
			plain, err := classify(r.secrets, aad, row.Secret, isSealed, &report)
			if err != nil {
				return unreadable("user_bot_credentials", row.BotID, err)
			}
			if !rewrite || dryRun || (isSealed && r.secrets.IsCurrent(row.Secret)) {
				continue
			}
			if !isSealed {
				plain = []byte(row.Secret)
			}
			stored, err := r.secrets.Seal(plain, aad)
			if err != nil {
				return err
			}
			if err := tx.Model(&botCredentialRow{}).Where("bot_id = ?", row.BotID).UpdateColumn("ciphertext", stored).Error; err != nil {
				return err
			}
			report.Rewritten++
		}
		return nil
	})
	return report, err
}
