//! W3C-PROV-inspired evidence registry without RDF/ontology machinery.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    error::{ModelError, ModelResult},
    ids::{ActivityId, AgentId, EntityId, RunId},
};

/// Origin category for an activity or evidence entity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    /// Evidence inferred from artifact contents without executing the target.
    StaticAnalysis,
    /// Evidence observed from real or sandboxed traffic/execution.
    DynamicCapture,
    /// Evidence derived by a fusion or resolution activity.
    Fusion,
}

/// Kind of provenance agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    /// Independently versioned external tool.
    ExternalTool,
    /// `APIaxess` engine component or future brain.
    Engine,
}

/// Tool or engine component responsible for an activity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    /// Stable agent/tool ID.
    pub id: AgentId,
    /// Agent category.
    pub kind: AgentKind,
    /// Human-readable tool or component name.
    pub name: String,
    /// Exact detected version when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// One tool run, capture, or fusion operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activity {
    /// Stable activity ID.
    pub id: ActivityId,
    /// Session-independent run ID.
    pub run_id: RunId,
    /// Agent that performed the activity.
    pub agent: AgentId,
    /// Static, dynamic, or fusion origin.
    pub source_type: SourceType,
    /// Activity start time.
    pub started_at: DateTime<Utc>,
    /// Activity completion time, when complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
}

/// Role of an entity in the evidence graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    /// Input artifact or imported evidence object.
    SourceArtifact,
    /// Direct assertion supporting a candidate fact.
    FactEvidence,
    /// Captured schema sample.
    ObservedSample,
    /// Fact derived from other entities by fusion.
    DerivedFact,
}

/// Provenance for one retained evidence entity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entity {
    /// Stable entity ID.
    pub id: EntityId,
    /// Entity role.
    pub kind: EntityKind,
    /// Source category, duplicated intentionally for per-fact inspection.
    pub source_type: SourceType,
    /// Activity that generated this entity.
    pub generated_by: ActivityId,
    /// Agent/tool that generated this entity.
    pub attributed_to: AgentId,
    /// Exact run that generated this entity.
    pub run_id: RunId,
    /// Entities from which this entity was derived.
    pub derived_from: Vec<EntityId>,
    /// Time at which the assertion or observation was recorded.
    pub recorded_at: DateTime<Utc>,
    /// Number of observations summarized by this entity.
    pub sample_count: NonZeroU64,
}

/// Normalized provenance graph referenced by every fact candidate.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRegistry {
    /// Known tools and engine agents.
    pub agents: Vec<Agent>,
    /// Known runs/activities.
    pub activities: Vec<Activity>,
    /// Evidence and derived entities.
    pub entities: Vec<Entity>,
}

impl ProvenanceRegistry {
    /// Returns an entity by ID.
    #[must_use]
    pub fn entity(&self, id: &EntityId) -> Option<&Entity> {
        self.entities.iter().find(|entity| &entity.id == id)
    }

    /// Returns an activity by ID.
    #[must_use]
    pub fn activity(&self, id: &ActivityId) -> Option<&Activity> {
        self.activities.iter().find(|activity| &activity.id == id)
    }

    /// Returns the leaf evidence reachable from the supplied entities.
    ///
    /// # Errors
    ///
    /// Fails on a missing reference or provenance cycle.
    pub fn leaf_entities<'a>(&'a self, roots: &[EntityId]) -> ModelResult<Vec<&'a Entity>> {
        let index = self.entity_index();
        self.leaf_entities_with_index(roots, &index)
    }

    /// Builds the immutable entity lookup used by repeated provenance walks.
    ///
    /// Callers processing many facts should build this once and pass it to
    /// [`Self::leaf_entities_with_index`]. Rebuilding it for every candidate
    /// makes a high-volume document needlessly quadratic in entity count.
    #[must_use]
    pub fn entity_index(&self) -> BTreeMap<&EntityId, &Entity> {
        self.entities
            .iter()
            .map(|entity| (&entity.id, entity))
            .collect()
    }

    /// Returns leaf evidence using a caller-owned immutable entity index.
    ///
    /// # Errors
    ///
    /// Fails on a missing reference or provenance cycle.
    pub fn leaf_entities_with_index<'a>(
        &self,
        roots: &[EntityId],
        index: &BTreeMap<&'a EntityId, &'a Entity>,
    ) -> ModelResult<Vec<&'a Entity>> {
        let mut leaves = BTreeSet::new();
        let mut visiting = BTreeSet::new();

        for root in roots {
            visit_leaves(root, index, &mut visiting, &mut leaves)?;
        }

        Ok(leaves
            .into_iter()
            .filter_map(|id| index.get(id).copied())
            .collect())
    }

    // The registry invariants are coupled and are deliberately validated in
    // one pass before any durable model can reference the registry.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn validate(&self) -> ModelResult<()> {
        let mut agent_ids = BTreeSet::new();
        for (index, agent) in self.agents.iter().enumerate() {
            if !agent_ids.insert(&agent.id) {
                return Err(ModelError::invariant(
                    format!("provenance.agents[{index}].id"),
                    "agent IDs must be unique",
                ));
            }
            if agent.name.trim().is_empty() {
                return Err(ModelError::invariant(
                    format!("provenance.agents[{index}].name"),
                    "agent name must not be blank",
                ));
            }
        }

        let mut activity_ids = BTreeSet::new();
        for (index, activity) in self.activities.iter().enumerate() {
            if !activity_ids.insert(&activity.id) {
                return Err(ModelError::invariant(
                    format!("provenance.activities[{index}].id"),
                    "activity IDs must be unique",
                ));
            }
            if !agent_ids.contains(&activity.agent) {
                return Err(ModelError::invariant(
                    format!("provenance.activities[{index}].agent"),
                    "activity agent is not registered",
                ));
            }
            if activity
                .ended_at
                .is_some_and(|ended_at| ended_at < activity.started_at)
            {
                return Err(ModelError::invariant(
                    format!("provenance.activities[{index}].ended_at"),
                    "activity cannot end before it starts",
                ));
            }
        }

        let activities: BTreeMap<_, _> = self
            .activities
            .iter()
            .map(|activity| (&activity.id, activity))
            .collect();
        let mut entity_ids = BTreeSet::new();
        for (index, entity) in self.entities.iter().enumerate() {
            if !entity_ids.insert(&entity.id) {
                return Err(ModelError::invariant(
                    format!("provenance.entities[{index}].id"),
                    "entity IDs must be unique",
                ));
            }
            let activity = activities.get(&entity.generated_by).ok_or_else(|| {
                ModelError::invariant(
                    format!("provenance.entities[{index}].generated_by"),
                    "generating activity is not registered",
                )
            })?;
            if entity.attributed_to != activity.agent
                || entity.run_id != activity.run_id
                || entity.source_type != activity.source_type
            {
                return Err(ModelError::invariant(
                    format!("provenance.entities[{index}]"),
                    "entity source, agent, and run must match its generating activity",
                ));
            }
            if entity.recorded_at < activity.started_at
                || activity
                    .ended_at
                    .is_some_and(|ended_at| entity.recorded_at > ended_at)
            {
                return Err(ModelError::invariant(
                    format!("provenance.entities[{index}].recorded_at"),
                    "entity timestamp must fall within its generating activity",
                ));
            }
            if entity.kind == EntityKind::DerivedFact && entity.derived_from.is_empty() {
                return Err(ModelError::invariant(
                    format!("provenance.entities[{index}].derived_from"),
                    "a derived fact must identify at least one source entity",
                ));
            }
        }

        let entity_index: BTreeMap<_, _> = self
            .entities
            .iter()
            .map(|entity| (&entity.id, entity))
            .collect();
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for (index, entity) in self.entities.iter().enumerate() {
            for derived in &entity.derived_from {
                if !entity_ids.contains(derived) {
                    return Err(ModelError::invariant(
                        format!("provenance.entities[{index}].derived_from"),
                        format!("derived entity `{derived}` is not registered"),
                    ));
                }
            }
            visit_provenance_graph(&entity.id, &entity_index, &mut visiting, &mut visited)?;
        }
        Ok(())
    }

    pub(crate) fn validate_activity_time(
        &self,
        activity_id: &ActivityId,
        at: DateTime<Utc>,
        path: &str,
    ) -> ModelResult<()> {
        let activity = self
            .activity(activity_id)
            .ok_or_else(|| ModelError::invariant(path, "referenced activity is not registered"))?;
        if at < activity.started_at || activity.ended_at.is_some_and(|ended_at| at > ended_at) {
            return Err(ModelError::invariant(
                path,
                "timestamp must fall within the referenced activity",
            ));
        }
        Ok(())
    }
}

fn visit_leaves<'a>(
    id: &'a EntityId,
    index: &BTreeMap<&'a EntityId, &'a Entity>,
    visiting: &mut BTreeSet<&'a EntityId>,
    leaves: &mut BTreeSet<&'a EntityId>,
) -> ModelResult<()> {
    let entity = index.get(id).copied().ok_or_else(|| {
        ModelError::invariant("provenance", format!("entity `{id}` is not registered"))
    })?;
    if !visiting.insert(id) {
        return Err(ModelError::invariant(
            "provenance",
            format!("derived-from cycle reaches entity `{id}`"),
        ));
    }
    if entity.derived_from.is_empty() {
        leaves.insert(id);
    } else {
        for parent in &entity.derived_from {
            visit_leaves(parent, index, visiting, leaves)?;
        }
    }
    visiting.remove(id);
    Ok(())
}

fn visit_provenance_graph(
    id: &EntityId,
    index: &BTreeMap<&EntityId, &Entity>,
    visiting: &mut BTreeSet<EntityId>,
    visited: &mut BTreeSet<EntityId>,
) -> ModelResult<()> {
    if visited.contains(id) {
        return Ok(());
    }
    let entity = index.get(id).copied().ok_or_else(|| {
        ModelError::invariant("provenance", format!("entity `{id}` is not registered"))
    })?;
    if !visiting.insert(id.clone()) {
        return Err(ModelError::invariant(
            "provenance",
            format!("derived-from cycle reaches entity `{id}`"),
        ));
    }
    for parent in &entity.derived_from {
        visit_provenance_graph(parent, index, visiting, visited)?;
    }
    visiting.remove(id);
    visited.insert(id.clone());
    Ok(())
}
